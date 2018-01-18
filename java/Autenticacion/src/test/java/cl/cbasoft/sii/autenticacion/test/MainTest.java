package cl.cbasoft.sii.autenticacion.test;

import java.io.FileInputStream;

import cl.cbasoft.sii.autenticacion.Respuesta;
import cl.cbasoft.sii.autenticacion.SimpleAutenticacion;
import cl.cbasoft.sii.autenticacion.exceptions.AutenticacionException;

public class MainTest {

	public static void main(String[] args) throws Exception {
		String token = SimpleAutenticacion
			.init(false)
			.validarSSL(false)
			.esperaEntrePeticionesHTTP(-1)
			.certificadoDigital(new FileInputStream("/certificado.pfx"), "cbaSoft")
			.getToken();
		System.out.println(token);
		
		SimpleAutenticacion
			.init(false)
			.validarSSL(false)
			.esperaEntrePeticionesHTTP(-1)
			.certificadoDigital(new FileInputStream("/certificado.pfx"), "cbaSoft")
			.asyncGetToken(new Respuesta() {
				
				@Override
				public void ok(String token) {
					System.out.println(token);
				}
				
				@Override
				public void error(AutenticacionException ex) {
					ex.printStackTrace();
				}
			});
		
	}

}
