package cl.cbasoft.sii.autenticacion.exceptions;

public class AutenticacionException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	private Integer httpStatus;
	private String  SIIEstado;
	private String  SIIGlosa;
	private String  SIIRespuesta;
	
	public AutenticacionException(String msg) {
		super(msg);
	}
	
	public AutenticacionException(int httpStatus, String msg) {
		super(msg);
		this.httpStatus = httpStatus;
	}
	
	public AutenticacionException(int httpStatus) {
		super("HTTP ERROR " + httpStatus);
		this.httpStatus = httpStatus;
	}
	
	public AutenticacionException(String mensaje, String SIIEstado, String SIIGlosa) {
		super(
			(mensaje   == null ? "" : mensaje) + 
			(SIIEstado == null ? "" : " [ESTADO]: " + SIIEstado) +
			(SIIGlosa  == null ? "" : " [GLOSA]: "  + SIIGlosa)
		);
		this.SIIEstado	= SIIEstado;
		this.SIIGlosa	= SIIGlosa;
	}
	
	public AutenticacionException(String msg, String SIIRespuesta) {
		super(msg + " [RESPUESTA]: " + SIIRespuesta);
		this.SIIRespuesta = SIIRespuesta;
	}
	
	public int getHttpStatus() {
		return httpStatus;
	}
	
	public String getSIIEstado() {
		return SIIEstado;
	}
	
	public String getSIIGlosa() {
		return SIIGlosa;
	}
	
	public String getSIIRespuesta() {
		return SIIRespuesta;
	}
}
