package cl.cbasoft.sii.autenticacion;

import cl.cbasoft.sii.autenticacion.exceptions.AutenticacionException;

public interface Respuesta {

	public void error(AutenticacionException ex);
	public void ok(String token);
	
}
