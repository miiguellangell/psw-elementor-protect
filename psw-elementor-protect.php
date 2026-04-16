<?php
/**
 * Plugin Name: PSW Elementor Protect
 * Description: Protege páginas con plantillas de Elementor mediante un popup de contraseña.
 * Version:     1.0.0
 * Author:      PSW
 * Text Domain: psw-elementor-protect
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'PSW_EP_VERSION',       '1.0.0' );
define( 'PSW_EP_OPT_PASSWORD',  'psw_ep_password' );
define( 'PSW_EP_OPT_PAGES',     'psw_ep_pages' );
define( 'PSW_EP_OPT_TOKEN',     'psw_ep_cookie_token' );
define( 'PSW_EP_COOKIE',        'psw_ep_access' );
define( 'PSW_EP_COOKIE_EXPIRY', DAY_IN_SECONDS );
define( 'PSW_EP_PLUGIN_URL',    plugin_dir_url( __FILE__ ) );

class PSW_Elementor_Protect {

	private static $instance = null;

	/** Caché para evitar evaluar las condiciones dos veces por request. */
	private $page_is_protected = null;

	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		add_action( 'admin_menu',                    [ $this, 'add_admin_menu' ] );
		add_action( 'admin_init',                    [ $this, 'handle_settings_save' ] );
		add_action( 'template_redirect',             [ $this, 'maybe_redirect_after_access' ] );
		add_action( 'template_redirect',             [ $this, 'litespeed_nocache' ], 1 );
		add_action( 'wp_enqueue_scripts',            [ $this, 'enqueue_scripts' ] );
		add_action( 'wp_footer',                     [ $this, 'render_popup' ] );
		add_action( 'wp_footer',                     [ $this, 'render_debug_comment' ], 999 );
		add_action( 'wp_ajax_psw_ep_verify',         [ $this, 'ajax_verify_password' ] );
		add_action( 'wp_ajax_nopriv_psw_ep_verify',  [ $this, 'ajax_verify_password' ] );
	}

	// ─────────────────────────────────────────────────────────────
	// Admin
	// ─────────────────────────────────────────────────────────────

	public function add_admin_menu() {
		add_options_page(
			__( 'Elementor Protect', 'psw-elementor-protect' ),
			__( 'Elementor Protect', 'psw-elementor-protect' ),
			'manage_options',
			'psw-elementor-protect',
			[ $this, 'render_settings_page' ]
		);
	}

	public function handle_settings_save() {
		if (
			! isset( $_POST['psw_ep_nonce'] ) ||
			! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['psw_ep_nonce'] ) ), 'psw_ep_save_settings' ) ||
			! current_user_can( 'manage_options' )
		) {
			return;
		}

		// Guardar IDs de páginas
		$raw_pages = isset( $_POST['psw_ep_pages'] ) ? sanitize_text_field( wp_unslash( $_POST['psw_ep_pages'] ) ) : '';
		update_option( PSW_EP_OPT_PAGES, $this->sanitize_page_ids( $raw_pages ) );

		// Guardar contraseña solo si se ingresó una nueva
		if ( ! empty( $_POST['psw_ep_password'] ) ) {
			$plain = sanitize_text_field( wp_unslash( $_POST['psw_ep_password'] ) );
			update_option( PSW_EP_OPT_PASSWORD, wp_hash_password( $plain ) );
			// Regenerar token para invalidar todas las cookies activas
			update_option( PSW_EP_OPT_TOKEN, bin2hex( random_bytes( 16 ) ) );
		}

		// Purgar caché de LiteSpeed al guardar (contraseña o IDs cambiaron)
		$this->litespeed_purge_all();

		add_settings_error(
			'psw_ep_settings',
			'psw_ep_saved',
			__( 'Ajustes guardados correctamente.', 'psw-elementor-protect' ),
			'updated'
		);
	}

	private function sanitize_page_ids( $value ) {
		$ids = array_filter( array_map( 'intval', explode( ',', $value ) ) );
		return implode( ',', $ids );
	}

	public function render_settings_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		settings_errors( 'psw_ep_settings' );

		$pages_value = get_option( PSW_EP_OPT_PAGES, '' );
		$has_password = ! empty( get_option( PSW_EP_OPT_PASSWORD, '' ) );

		// Mostrar títulos de las páginas protegidas
		$page_labels = [];
		if ( $pages_value ) {
			foreach ( explode( ',', $pages_value ) as $id ) {
				$id    = intval( $id );
				$title = get_the_title( $id );
				$page_labels[] = $title
					? '<strong>' . $id . '</strong> — ' . esc_html( $title )
					: '<strong>' . $id . '</strong>';
			}
		}
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'Elementor Protect — Configuración', 'psw-elementor-protect' ); ?></h1>

			<form method="post" action="">
				<?php wp_nonce_field( 'psw_ep_save_settings', 'psw_ep_nonce' ); ?>

				<table class="form-table" role="presentation">

					<!-- Campo: Contraseña -->
					<tr>
						<th scope="row">
							<label for="psw_ep_password">
								<?php esc_html_e( 'Contraseña de acceso', 'psw-elementor-protect' ); ?>
							</label>
						</th>
						<td>
							<input
								type="password"
								name="psw_ep_password"
								id="psw_ep_password"
								class="regular-text"
								autocomplete="new-password"
								placeholder="<?php echo $has_password
									? esc_attr__( 'Dejar en blanco para mantener la actual', 'psw-elementor-protect' )
									: esc_attr__( 'Ingresa una contraseña', 'psw-elementor-protect' ); ?>"
							/>
							<?php if ( $has_password ) : ?>
								<p class="description">
									<?php esc_html_e( 'Ya existe una contraseña configurada. Escribe una nueva solo si deseas cambiarla.', 'psw-elementor-protect' ); ?>
								</p>
							<?php endif; ?>
						</td>
					</tr>

					<!-- Campo: IDs de páginas -->
					<tr>
						<th scope="row">
							<label for="psw_ep_pages">
								<?php esc_html_e( 'IDs de páginas a proteger', 'psw-elementor-protect' ); ?>
							</label>
						</th>
						<td>
							<input
								type="text"
								name="psw_ep_pages"
								id="psw_ep_pages"
								class="regular-text"
								value="<?php echo esc_attr( $pages_value ); ?>"
								placeholder="<?php esc_attr_e( 'Ej: 12, 45, 78', 'psw-elementor-protect' ); ?>"
							/>
							<p class="description">
								<?php esc_html_e( 'Ingresa los IDs separados por coma. Acepta dos tipos:', 'psw-elementor-protect' ); ?>
					<br>
					&bull; <strong><?php esc_html_e( 'ID de página/post', 'psw-elementor-protect' ); ?></strong> — <?php esc_html_e( 'visible en la URL al editar (?post=XXX).', 'psw-elementor-protect' ); ?>
					<br>
					&bull; <strong><?php esc_html_e( 'ID de plantilla de Elementor Theme Builder', 'psw-elementor-protect' ); ?></strong> — <?php esc_html_e( 'bloquea cualquier página/post que use esa plantilla (requiere Elementor Pro).', 'psw-elementor-protect' ); ?>
							</p>
							<?php if ( ! empty( $page_labels ) ) : ?>
								<p class="description" style="margin-top:8px;">
									<strong><?php esc_html_e( 'Páginas protegidas actualmente:', 'psw-elementor-protect' ); ?></strong><br>
									<?php echo implode( ' &nbsp;|&nbsp; ', $page_labels ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- already escaped above ?>
								</p>
							<?php endif; ?>
						</td>
					</tr>

				</table>

				<?php submit_button( __( 'Guardar cambios', 'psw-elementor-protect' ) ); ?>
			</form>
		</div>
		<?php
	}

	// ─────────────────────────────────────────────────────────────
	// Frontend
	// ─────────────────────────────────────────────────────────────

	/**
	 * Si la URL tiene ?psw_ep_ok=1 y la cookie es válida, redirige a la URL
	 * limpia (sin el parámetro). Esto evita que el parámetro anti-caché quede
	 * visible y fuerza una nueva petición PHP en la URL canónica.
	 */
	public function maybe_redirect_after_access() {
		if ( ! isset( $_GET['psw_ep_ok'] ) ) {
			return;
		}
		// Construir URL limpia sin el param
		$url = remove_query_arg( 'psw_ep_ok' );
		wp_safe_redirect( $url, 302 );
		exit;
	}

	private function is_protected_page() {
		if ( null !== $this->page_is_protected ) {
			return $this->page_is_protected;
		}

		$protected = get_option( PSW_EP_OPT_PAGES, '' );

		error_log( sprintf(
			'[PSW-EP] is_protected_page | url=%s | queried_id=%d | is_singular=%s | protected_ids=%s | elementor_pro=%s',
			isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '?',
			get_queried_object_id(),
			is_singular() ? 'yes' : 'no',
			$protected ?: '(empty)',
			class_exists( '\ElementorPro\Modules\ThemeBuilder\Module' ) ? 'yes' : 'no'
		) );

		if ( empty( $protected ) ) {
			$this->page_is_protected = false;
			return false;
		}

		$ids = array_filter( array_map( 'intval', explode( ',', $protected ) ) );
		if ( empty( $ids ) ) {
			$this->page_is_protected = false;
			return false;
		}

		// 1. Coincidencia por ID directo de página / post.
		if ( is_singular() && in_array( get_queried_object_id(), $ids, true ) ) {
			error_log( '[PSW-EP] MATCH via direct post ID' );
			$this->page_is_protected = true;
			return true;
		}

		// 2. Coincidencia por plantilla de Elementor Theme Builder.
		$template_match = $this->is_elementor_template_active( $ids );
		error_log( '[PSW-EP] is_elementor_template_active = ' . ( $template_match ? 'true' : 'false' ) );

		if ( $template_match ) {
			$this->page_is_protected = true;
			return true;
		}

		$this->page_is_protected = false;
		return false;
	}

	/**
	 * Comprueba si alguno de los IDs dados corresponde a una plantilla de
	 * Elementor Theme Builder activa para la página actual.
	 * Usa 3 métodos en orden de disponibilidad.
	 *
	 * @param int[] $template_ids
	 * @return bool
	 */
	private function is_elementor_template_active( array $template_ids ) {

		// ── Método 1: API de Elementor Pro ────────────────────────────
		if ( class_exists( '\ElementorPro\Modules\ThemeBuilder\Module' ) ) {
			$locations = [ 'single', 'archive', 'header', 'footer', 'search-results', 'error-404' ];
			try {
				$conditions_manager = \ElementorPro\Modules\ThemeBuilder\Module::instance()
					->get_conditions_manager();
				foreach ( $locations as $location ) {
					$documents = $conditions_manager->get_documents_for_location( $location );
					if ( ! is_array( $documents ) ) continue;
					foreach ( $documents as $doc ) {
						$doc_id = (int) $doc->get_main_id();
						error_log( "[PSW-EP] M1 location={$location} doc_id={$doc_id}" );
						if ( in_array( $doc_id, $template_ids, true ) ) {
							return true;
						}
					}
				}
			} catch ( \Throwable $e ) {
				error_log( '[PSW-EP] M1 exception: ' . $e->getMessage() );
			}
		}

		// ── Método 2: Post meta _elementor_conditions (sin API) ───────
		// Elementor Pro guarda las condiciones de cada plantilla como meta.
		foreach ( $template_ids as $tpl_id ) {
			$raw = get_post_meta( $tpl_id, '_elementor_conditions', true );
			error_log( "[PSW-EP] M2 template={$tpl_id} _elementor_conditions=" . print_r( $raw, true ) );
			if ( ! empty( $raw ) && is_array( $raw ) ) {
				if ( $this->matches_elementor_conditions( $raw ) ) {
					return true;
				}
			}
		}

		// ── Método 3: Opción global elementor_pro_theme_builder_conditions_v2 ──
		$global = get_option( 'elementor_pro_theme_builder_conditions_v2', [] );
		error_log( '[PSW-EP] M3 global conditions option: ' . print_r( $global, true ) );
		if ( is_array( $global ) ) {
			foreach ( $global as $location => $tpl_map ) {
				if ( ! is_array( $tpl_map ) ) continue;
				foreach ( array_keys( $tpl_map ) as $tpl_id ) {
					if ( in_array( (int) $tpl_id, $template_ids, true ) ) {
						error_log( "[PSW-EP] M3 MATCH location={$location} tpl_id={$tpl_id}" );
						// La plantilla existe, pero debemos verificar si aplica a esta página.
						$raw = get_post_meta( (int) $tpl_id, '_elementor_conditions', true );
						if ( ! empty( $raw ) && is_array( $raw ) && $this->matches_elementor_conditions( $raw ) ) {
							return true;
						}
						// Si no hay condiciones específicas, proteger todo lo que usa esta plantilla.
						if ( empty( $raw ) ) {
							return true;
						}
					}
				}
			}
		}

		return false;
	}

	/**
	 * Evalúa si las condiciones de una plantilla de Elementor coinciden
	 * con la página actual. Sólo procesa condiciones "include".
	 *
	 * Formato de cada condición: "include/general/" | "include/singular/"
	 *   | "include/singular/post/" | "include/singular/my_cpt/123/"
	 *
	 * @param array $conditions
	 * @return bool
	 */
	private function matches_elementor_conditions( array $conditions ) {
		foreach ( $conditions as $raw ) {
			$parts = array_values( array_filter( explode( '/', $raw ) ) );
			if ( empty( $parts ) || $parts[0] !== 'include' ) continue;

			$sub = $parts[1] ?? '';

			// include/general → aplica a todo el sitio
			if ( 'general' === $sub ) return true;

			// include/singular → aplica a cualquier entrada singular
			if ( 'singular' === $sub ) {
				if ( ! is_singular() ) continue;
				$post_type    = $parts[2] ?? '';
				$specific_id  = isset( $parts[3] ) ? (int) $parts[3] : 0;

				// include/singular/ sin tipo → cualquier singular
				if ( '' === $post_type ) return true;

				// include/singular/post_type/
				if ( get_post_type() === $post_type ) {
					if ( 0 === $specific_id ) return true;
					if ( $specific_id === get_queried_object_id() ) return true;
				}
			}

			// include/archive → archivos
			if ( 'archive' === $sub && is_archive() ) return true;
		}
		return false;
	}

	private function has_valid_cookie() {
		if ( ! isset( $_COOKIE[ PSW_EP_COOKIE ] ) ) {
			return false;
		}
		$cookie   = sanitize_text_field( wp_unslash( $_COOKIE[ PSW_EP_COOKIE ] ) );
		$expected = $this->generate_cookie_value();
		return hash_equals( $expected, $cookie );
	}

	private function generate_cookie_value() {
		// Usa un token simple almacenado en DB — estable entre requests y solo
		// cambia cuando el admin actualiza la contraseña, invalidando cookies activas.
		$token = get_option( PSW_EP_OPT_TOKEN, 'default' );
		return hash( 'sha256', AUTH_KEY . $token . date( 'Y-m-d' ) );
	}

	public function enqueue_scripts() {
		if ( ! $this->is_protected_page() || $this->has_valid_cookie() ) {
			return;
		}

		$plugin_dir = plugin_dir_path( __FILE__ );
		$css_ver    = file_exists( $plugin_dir . 'assets/popup.css' ) ? filemtime( $plugin_dir . 'assets/popup.css' ) : PSW_EP_VERSION;
		$js_ver     = file_exists( $plugin_dir . 'assets/popup.js' )  ? filemtime( $plugin_dir . 'assets/popup.js' )  : PSW_EP_VERSION;

		wp_enqueue_style(
			'psw-ep-popup',
			PSW_EP_PLUGIN_URL . 'assets/popup.css',
			[],
			$css_ver
		);

		wp_enqueue_script(
			'psw-ep-popup',
			PSW_EP_PLUGIN_URL . 'assets/popup.js',
			[ 'jquery' ],
			$js_ver,
			true
		);

		wp_localize_script( 'psw-ep-popup', 'pswEP', [
			'ajax_url' => admin_url( 'admin-ajax.php' ),
			'nonce'    => wp_create_nonce( 'psw_ep_verify' ),
			'home_url' => home_url( '/?psw_ep_ok=1' ),
			'labels'   => [
				'wrong_password' => __( 'Contraseña incorrecta. Inténtalo de nuevo.', 'psw-elementor-protect' ),
				'server_error'   => __( 'Ocurrió un error. Inténtalo de nuevo.', 'psw-elementor-protect' ),
			],
		] );
	}

	public function render_popup() {
		if ( ! $this->is_protected_page() || $this->has_valid_cookie() ) {
			return;
		}
		?>
		<div id="psw-ep-overlay" role="dialog" aria-modal="true" aria-labelledby="psw-ep-title">
			<div id="psw-ep-modal">
				<h2 id="psw-ep-title"><?php esc_html_e( 'Contenido protegido', 'psw-elementor-protect' ); ?></h2>
				<p><?php esc_html_e( 'Ingresa la contraseña para acceder a este contenido.', 'psw-elementor-protect' ); ?></p>
				<form id="psw-ep-form" novalidate>
					<div class="psw-ep-field">
						<label for="psw-ep-input" class="psw-ep-sr-only">
							<?php esc_html_e( 'Contraseña', 'psw-elementor-protect' ); ?>
						</label>
						<input
							type="password"
							id="psw-ep-input"
							name="psw_ep_password"
							placeholder="<?php esc_attr_e( 'Contraseña', 'psw-elementor-protect' ); ?>"
							autocomplete="current-password"
							required
						/>
					</div>
					<p id="psw-ep-error" role="alert" aria-live="assertive"></p>
					<button type="submit" id="psw-ep-submit">
						<?php esc_html_e( 'Acceder', 'psw-elementor-protect' ); ?>
					</button>
				</form>
			</div>
		</div>
		<?php
	}

	// ─────────────────────────────────────────────────────────────
	// AJAX
	// ─────────────────────────────────────────────────────────────

	public function ajax_verify_password() {
		check_ajax_referer( 'psw_ep_verify', 'nonce' );

		$password = isset( $_POST['password'] ) ? sanitize_text_field( wp_unslash( $_POST['password'] ) ) : '';

		if ( empty( $password ) ) {
			wp_send_json_error( [ 'message' => __( 'Ingresa una contraseña.', 'psw-elementor-protect' ) ] );
		}

		$stored = get_option( PSW_EP_OPT_PASSWORD, '' );

		if ( empty( $stored ) || ! wp_check_password( $password, $stored ) ) {
			// Pequeño retraso para dificultar ataques de fuerza bruta
			sleep( 1 );
			wp_send_json_error( [ 'message' => __( 'Contraseña incorrecta. Inténtalo de nuevo.', 'psw-elementor-protect' ) ] );
		}

		$cookie_value  = $this->generate_cookie_value();
		$cookie_expiry = time() + PSW_EP_COOKIE_EXPIRY;
		// Siempre '/' para que la cookie sea válida en todo el sitio,
		// independientemente de si WordPress está en una subcarpeta.
		$cookie_path   = '/';
		$cookie_domain = defined( 'COOKIE_DOMAIN' ) && COOKIE_DOMAIN ? COOKIE_DOMAIN : '';

		$result = setcookie( PSW_EP_COOKIE, $cookie_value, [
			'expires'  => $cookie_expiry,
			'path'     => $cookie_path,
			'domain'   => $cookie_domain,
			'secure'   => is_ssl(),
			'httponly' => true,
			'samesite' => 'Strict',
		] );

		error_log( sprintf(
			'[PSW-EP] setcookie result=%s | name=%s | value=%s | path=%s | domain=%s | secure=%s | expires=%s',
			$result ? 'true' : 'false',
			PSW_EP_COOKIE,
			substr( $cookie_value, 0, 8 ) . '...',
			$cookie_path,
			$cookie_domain ?: '(empty)',
			is_ssl() ? 'yes' : 'no',
			date( 'Y-m-d H:i:s', $cookie_expiry )
		) );

		wp_send_json_success( [
			'message'       => __( 'Acceso concedido.', 'psw-elementor-protect' ),
			'_debug_cookie' => [
				'set_result'  => $result,
				'name'        => PSW_EP_COOKIE,
				'path'        => $cookie_path,
				'domain'      => $cookie_domain ?: '(empty)',
				'expires_in'  => PSW_EP_COOKIE_EXPIRY . 's',
				'php_version' => PHP_VERSION,
				'note'        => 'La cookie es httponly — no aparece en document.cookie del navegador, pero el servidor SI la recibe.',
			],
		] );
	}

	// ─────────────────────────────────────────────────────────────
	// LiteSpeed Cache
	// ─────────────────────────────────────────────────────────────

	/**
	 * Indica a LiteSpeed que NO cachee las páginas protegidas.
	 * Se ejecuta en template_redirect antes de que LiteSpeed decida cachear.
	 */
	public function litespeed_nocache() {
		if ( ! $this->is_protected_page() ) {
			return;
		}
		// API del plugin LiteSpeed Cache
		do_action( 'litespeed_control_set_nocache', 'psw-ep: página protegida por contraseña' );

		// Cabeceras directas como fallback (LiteSpeed Server nativo)
		if ( ! headers_sent() ) {
			header( 'X-LiteSpeed-Cache-Control: no-cache' );
			header( 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0' );
			header( 'Pragma: no-cache' );
		}
	}

	/**
	 * Purga toda la caché de LiteSpeed.
	 * Se llama al guardar ajustes del plugin.
	 */
	private function litespeed_purge_all() {
		// API del plugin LiteSpeed Cache
		do_action( 'litespeed_purge_all' );

		// Fallback: cabecera de purga nativa de LiteSpeed Server
		if ( ! headers_sent() ) {
			header( 'X-LiteSpeed-Purge: *' );
		}
	}


	public function render_debug_comment() {
		// TEMP: sin restricción para depuración — quitar después
		// if ( ! current_user_can( 'manage_options' ) ) {
		// 	return;
		// }

		$protected     = get_option( PSW_EP_OPT_PAGES, '' );
		$ids           = array_filter( array_map( 'intval', explode( ',', $protected ) ) );
		$queried_id    = get_queried_object_id();
		$is_singular   = is_singular();
		$elementor_pro = class_exists( '\ElementorPro\Modules\ThemeBuilder\Module' );
		$is_protected  = $this->is_protected_page();
		$has_cookie    = $this->has_valid_cookie();

		// Inspeccionar condiciones de cada template ID
		$conditions_info = [];
		foreach ( $ids as $id ) {
			$raw = get_post_meta( $id, '_elementor_conditions', true );
			$conditions_info[ $id ] = $raw;
		}

		$global = get_option( 'elementor_pro_theme_builder_conditions_v2', '(not found)' );

		printf(
			"\n<!-- PSW-EP DEBUG\n" .
			"  queried_object_id : %d\n" .
			"  is_singular       : %s\n" .
			"  post_type         : %s\n" .
			"  protected_ids     : %s\n" .
			"  elementor_pro_api : %s\n" .
			"  is_protected_page : %s\n" .
			"  has_valid_cookie  : %s\n" .
			"  _elementor_conditions per id:\n%s\n" .
			"  global_conditions_v2: %s\n" .
			"-->\n",
			$queried_id,
			$is_singular ? 'yes' : 'no',
			esc_html( (string) get_post_type() ),
			esc_html( implode( ', ', $ids ) ),
			$elementor_pro ? 'yes' : 'no',
			$is_protected ? 'YES' : 'no',
			$has_cookie ? 'yes' : 'no',
			esc_html( print_r( $conditions_info, true ) ),
			esc_html( print_r( $global, true ) )
		);
	}
}

PSW_Elementor_Protect::get_instance();
