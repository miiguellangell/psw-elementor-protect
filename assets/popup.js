/* global pswEP, jQuery */
( function ( $ ) {
	'use strict';

	$( document ).ready( function () {
		var $overlay = $( '#psw-ep-overlay' );
		var $form    = $( '#psw-ep-form' );
		var $input   = $( '#psw-ep-input' );
		var $submit  = $( '#psw-ep-submit' );
		var $error   = $( '#psw-ep-error' );

		if ( ! $overlay.length ) {
			return;
		}

		// Bloquear scroll y enfocar el input
		$( 'body' ).addClass( 'psw-ep-locked' );
		setTimeout( function () {
			$input.trigger( 'focus' );
		}, 100 );

		// Submit del formulario
		$form.on( 'submit', function ( e ) {
			e.preventDefault();

			var password = $input.val().trim();
			if ( ! password ) {
				return;
			}

			$submit.prop( 'disabled', true );
			$error.text( '' );

			console.group( '[PSW-EP] Enviando contraseña...' );
			console.log( 'ajax_url :', pswEP.ajax_url );
			console.log( 'nonce    :', pswEP.nonce );

			$.ajax( {
				url:    pswEP.ajax_url,
				method: 'POST',
				data: {
					action:   'psw_ep_verify',
					nonce:    pswEP.nonce,
					password: password,
				},
				success: function ( response, status, xhr ) {
					console.log( 'Respuesta PHP   :', response );
					console.log( 'document.cookie :', document.cookie );
					console.groupEnd();

					if ( response.success ) {
					// Redirige al home con param anti-caché; PHP luego redirige a la URL limpia del home.
					setTimeout( function () {
						$overlay.fadeOut( 200, function () {
							$( 'body' ).removeClass( 'psw-ep-locked' );
							window.location.href = pswEP.home_url;
							} );
						}, 400 );
					} else {
						var msg = ( response.data && response.data.message )
							? response.data.message
							: pswEP.labels.wrong_password;
						$error.text( msg );
						$input.val( '' ).trigger( 'focus' );
						$submit.prop( 'disabled', false );
					}
				},
				error: function ( xhr, status, err ) {
					console.error( '[PSW-EP] Error AJAX :', status, err );
					console.log( 'Respuesta cruda :', xhr.responseText );
					console.groupEnd();
					$error.text( pswEP.labels.server_error );
					$submit.prop( 'disabled', false );
				},
			} );
		} );

		// Accesibilidad: "Enter" en el input envía el formulario
		$input.on( 'keydown', function ( e ) {
			if ( e.key === 'Enter' ) {
				$form.trigger( 'submit' );
			}
		} );
	} );

}( jQuery ) );
