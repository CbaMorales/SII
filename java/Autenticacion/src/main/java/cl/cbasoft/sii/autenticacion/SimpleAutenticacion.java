package cl.cbasoft.sii.autenticacion;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import cl.cbasoft.sii.autenticacion.exceptions.AutenticacionException;

public class SimpleAutenticacion {

	private boolean validarSSL 				= true;
	private Boolean certificacion 			= null;
	private int esperaEntrePeticionesHTTP 	= 1000;
	private X509Certificate x509;
	private PrivateKey llavePrivada;
	

	/**
	 * Crea una instancia de {@link SimpleAutenticacion}
	 * @param enCertificacion True para ambiente de certifcacion, False para ambiente de produccion
	 * @return Instancia de {@link SimpleAutenticacion}
	 */
	public static SimpleAutenticacion init(boolean enCertificacion) {
		SimpleAutenticacion obj = new SimpleAutenticacion();
		obj.certificacion		= enCertificacion;
		return obj;
	}
	
	/**
	 * Activa o desactiva la validacion de la conexion SSL hacia el SII.
	 * <br/>
	 * Se recomienda tener esta opcion activada (True)
	 * 
	 * @param validarSSL True para validar, False para omitir la validacion
	 * @return Instancia de {@link SimpleAutenticacion}
	 */
	public SimpleAutenticacion validarSSL(boolean validarSSL) {
		this.validarSSL = validarSSL;
		return this;
	}
	
	/**
	 * Especifica el tiempo de espera entre peticiones HTTP para evitar el bloqueo del SII por peticiones muy concurrentes
	 * @param miliSegundos de esperas entre peticion. Valores igual o menores a cero significa sin esperas
	 * @return Instancia de {@link SimpleAutenticacion}
	 */
	public SimpleAutenticacion esperaEntrePeticionesHTTP(int miliSegundos) {
		this.esperaEntrePeticionesHTTP = miliSegundos;
		return this;
	}
	
	/**
	 * Especificar un certificado x509 utilizado en la firma de la semilla
	 * @param x509 certificado publico del contribuyente
	 * @return Instancia de {@link SimpleAutenticacion}
	 */
	public SimpleAutenticacion x509(X509Certificate x509) {
		this.x509 = x509;
		return this;
	}
	
	/**
	 * Especificar la llave privada utilizada para firmar la semilla
	 * @param llavePrivada llave privada (PrivateKey) del certificado digital del contribuyente
	 * @return Instancia de {@link SimpleAutenticacion}
	 */
	public SimpleAutenticacion llavePrivada(PrivateKey llavePrivada) {
		this.llavePrivada = llavePrivada;
		return this;
	}
	
	/**
	 * Especificar un contenedor en formato PFX o P12. 
	 * <p>Tanto el certificado publico como la llave privada se extraeran de forma automatica
	 * @param inputStream Archivo PFX o P12
	 * @param clave Clave del PFX o P12
	 * @return Instancia de {@link SimpleAutenticacion}
	 */
	public SimpleAutenticacion certificadoDigital(InputStream inputStream, String clave) {
		try {
			KeyStore keyStore = KeyStore.getInstance("pkcs12");
			keyStore.load(inputStream, clave.toCharArray());
			inputStream.close();
			PasswordProtection protection	= new PasswordProtection(clave.toCharArray());
			Enumeration<String> aliass 		= keyStore.aliases();
			PrivateKeyEntry llave			= null;
			while(aliass.hasMoreElements()){
				try{
					String alias = aliass.nextElement();
					llave 		 = (PrivateKeyEntry) keyStore.getEntry(alias, protection);
				}catch(Exception ex) {}
			}
			if(llave == null)
				throw new AutenticacionException("LLAVE NO ENCONTRADA");
			
			this.x509((X509Certificate)llave.getCertificate())
				.llavePrivada(llave.getPrivateKey());
		} catch(IOException | CertificateException | KeyStoreException | NoSuchAlgorithmException ex) {
			throw new AutenticacionException("ERROR AL PROCESAR CERTIFICADO DIGITAL. " + ex.getMessage());
		}
		return this;
	}
	
	/**
	 * Solicitar Token al SII de forma sincronica
	 * @return Token entregado por el SII
	 * @throws IllegalArgumentException si no se han especificado el certificado x509 y/o la llave privada
	 * @throws AutenticacionException si se produce un error en la solicitud o respuesta del web services
	 */
	public String getToken() {
		if (x509 == null || llavePrivada == null)
			throw new IllegalArgumentException("DEBE ESPECIFICAR UN CERTIFICADO DIGITAL VALIDO");
		
		String semilla = Autenticacion.GetSemilla(certificacion, validarSSL);
		String firmada = Autenticacion.FirmarSemilla(semilla, x509, llavePrivada);
		
		if(esperaEntrePeticionesHTTP > 0)
			try { Thread.sleep(esperaEntrePeticionesHTTP); } catch (Exception ex) {}
		
		return Autenticacion.GetToken(certificacion, validarSSL, firmada);
	}
	
	/**
	 * Solicitar Token al SII de forma asincronica
	 * @throws IllegalArgumentException si no se han especificado el certificado x509 y/o la llave privada
	 * @throws IllegalArgumentException si no se ha especificado el parametro respuesta
	 */
	public void asyncGetToken(Respuesta respuesta) {
		if (respuesta == null)
			throw new IllegalArgumentException("DEBE ESPECIFICAR UN EVENTO DE RESPUESTA");
		if (x509 == null || llavePrivada == null)
			throw new IllegalArgumentException("DEBE ESPECIFICAR UN CERTIFICADO DIGITAL VALIDO");
		
		Thread peticion = new Thread(new Runnable() {
			@Override
			public void run() {
				try {
					String token = getToken();
					respuesta.ok(token);
				} catch (AutenticacionException aex) {
					respuesta.error(aex);
				}
			}
		});
		
		peticion.start();
	}
}
