package cl.cbasoft.sii.autenticacion;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import cl.cbasoft.sii.autenticacion.exceptions.AutenticacionException;

public class Autenticacion {
	
	private static DocumentBuilderFactory DOCUMENT_BUILDER_FACTORY 	= DocumentBuilderFactory.newInstance();
	private static XMLSignatureFactory XML_SIGNATURE_FACTORY		= XMLSignatureFactory.getInstance("DOM");
	
	private static String USER_AGENT = "Mozilla/5.0 (Windows NT 6.1; WOW64; PROG 1.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/43.0.2357.81 Safari/537.36";
	private static SSLSocketFactory SSLSocketFactory;
	private static HostnameVerifier HostnameVerifier;
	
	public static String GetSemilla(boolean certificacion, boolean validarSSL) {
		String wsUrl 	= "https://" + (certificacion ? "maullin" : "palena") + ".sii.cl/DTEWS/CrSeed.jws?wsdl";
		String wsMetodo = "getSeed";
		
		String wsCuerpo = "";
		wsCuerpo += "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\">";
		wsCuerpo += "<soapenv:Header/>";
		wsCuerpo += "<soapenv:Body>";
		wsCuerpo += "<getSeed/>";
		wsCuerpo += "</soapenv:Body>";
		wsCuerpo += "</soapenv:Envelope>";
		
		String xmlRes = SOAPEjecutor(wsUrl, wsMetodo, wsCuerpo, "getSeedReturn", validarSSL);
		Document dom  = null;
		
		try {
			dom = StringToDom(xmlRes);
		} catch(Exception ex) {
			throw new AutenticacionException("LA RESPUESTA NO PUDO SER PROCESADA. " + ex.getMessage());
		}
		
		Node nSemilla = GetNode(dom.getDocumentElement(), "SEMILLA");
		Node nEstado  = GetNode(dom.getDocumentElement(), "ESTADO");
		Node nGlosa	  = GetNode(dom.getDocumentElement(), "GLOSA");
		
		if(nSemilla == null) {
			String estado = nEstado == null ? null : nEstado.getTextContent();
			String glosa  = nGlosa  == null ? null : nGlosa.getTextContent();
			throw new AutenticacionException("ERROR AL OBTENER LA SEMILLA", estado, glosa);
		}
		
		return nSemilla.getTextContent();
	}
	
	public static String FirmarSemilla(String semilla, X509Certificate x509, PrivateKey llavePrivada) {
		try {
			Document dom   	 = DOCUMENT_BUILDER_FACTORY.newDocumentBuilder().newDocument();
			Element gettoken = dom.createElement("gettoken");
			Element item 	 = dom.createElement("item");
			Element Semilla  = dom.createElement("Semilla");
			Semilla.setTextContent(semilla);
			gettoken.appendChild(item);
			item.appendChild(Semilla);
			dom.appendChild(gettoken);
			
			Reference ref = XML_SIGNATURE_FACTORY.newReference(
	            "",
	            XML_SIGNATURE_FACTORY.newDigestMethod(DigestMethod.SHA512, null),
	            Collections.singletonList
	            (XML_SIGNATURE_FACTORY.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)),
	            null,
	            null
	        );
			
			SignedInfo si = XML_SIGNATURE_FACTORY.newSignedInfo(
				XML_SIGNATURE_FACTORY.newCanonicalizationMethod(
						CanonicalizationMethod.INCLUSIVE,
					(C14NMethodParameterSpec) null
				),
				XML_SIGNATURE_FACTORY.newSignatureMethod(SignatureMethod.RSA_SHA1, null),
				Collections.singletonList(ref)
	        );
			
			KeyInfoFactory kif 	= XML_SIGNATURE_FACTORY.getKeyInfoFactory();
			X509Data x509Data 	= kif.newX509Data(Collections.singletonList(x509));
	        KeyValue kv 		= kif.newKeyValue(x509.getPublicKey());
	        List<Object> lista 	= new ArrayList<Object>();
	        lista.add(kv);
	        lista.add(x509Data);
	        KeyInfo ki 				= kif.newKeyInfo(lista);
	        DOMSignContext dsc      = new DOMSignContext(llavePrivada, dom.getDocumentElement());
	        XMLSignature signature 	= XML_SIGNATURE_FACTORY.newXMLSignature(si, ki);
	        signature.sign(dsc);
	        
	        return DomToString(dom);
		} catch(Exception ex) {
			throw new AutenticacionException("NO FUE POSIBLE FIRMAR LA SEMILLA. " + ex.getMessage());
		}
	}
	
	public static String GetToken(boolean certificacion, boolean validarSSL, String semillaFirmada) {
		String xml   = "";
		Document dom = null;
    	xml = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\">";
			xml += "<soapenv:Header/>";
			xml += "<soapenv:Body>";
				xml += "<getToken>";
					xml += "<pszXml></pszXml>";
				xml += "</getToken>";
			xml += "</soapenv:Body>";
		xml += "</soapenv:Envelope>";
		
		
		try {
			dom = StringToDom(xml);
			Node pszXml  = GetNode(dom.getDocumentElement(), "pszXml");
			pszXml.setTextContent(semillaFirmada);
			xml = DomToString(dom);
		} catch (IOException | ParserConfigurationException | SAXException | TransformerException ex) {
			throw new AutenticacionException("ERROR AL PREPARAR SOLICITUD DE TOKEN");
		}
		
		String respuesta = null;
		try {
			String wsUrl 	 = "https://" + (certificacion ? "maullin" : "palena") + ".sii.cl/DTEWS/GetTokenFromSeed.jws?wsdl";
			String wsMetodo  = "getToken";
			String wsReturn  = "getTokenReturn";
			respuesta 		 = SOAPEjecutor(wsUrl, wsMetodo, xml, wsReturn, validarSSL);
			dom				 = StringToDom(respuesta);
		} catch (IOException | ParserConfigurationException | SAXException ex) {
			throw new AutenticacionException("ERROR AL PROCESAR LA RESPUESTA DEL SII", respuesta);
		}
		
		Node nToken  = GetNode(dom.getDocumentElement(), "TOKEN");
		Node nEstado = GetNode(dom.getDocumentElement(), "ESTADO");
		Node nGlosa	 = GetNode(dom.getDocumentElement(), "GLOSA");
		
		if(nToken == null) {
			String estado = nEstado == null ? null : nEstado.getTextContent();
			String glosa  = nGlosa  == null ? null : nGlosa.getTextContent();
			throw new AutenticacionException("ERROR AL OBTENER EL TOKEN", estado, glosa);
		}
		
		return nToken.getTextContent();
	}
	
	private static String SOAPEjecutor(String wsUrl, String wsMetodo, String wsCuerpo, String wsReturn, boolean validarSSL) {
		HttpURLConnection http = null;
		InputStream is 		   = null;
		try {
			URL url = new URL(wsUrl);
			http	= (HttpURLConnection) url.openConnection();
			
			if(!validarSSL && http instanceof HttpsURLConnection) {
				try {
					NoValidarSSL((HttpsURLConnection)http);
				} catch (Exception ex) {
					throw new AutenticacionException("ERROR AL CREAR CONEXION SSL. " + ex.getMessage());
				}
			}
			
			http.setDoOutput(true);
			http.setRequestMethod("POST");
			http.addRequestProperty("UserAgent", USER_AGENT);
			http.addRequestProperty("SOAPAction", wsMetodo);
			http.getOutputStream().write(wsCuerpo.getBytes());
			
			int httpStatus = http.getResponseCode();
			if(httpStatus >= 200 && httpStatus < 400) {
				is = http.getInputStream();
			} else {
				throw new AutenticacionException(httpStatus);
			}
			
			try {
				Document doc   = StreamToDom(is);
				Node respuesta = GetNode(doc.getDocumentElement(), wsReturn);
				if(respuesta == null)
					throw new AutenticacionException("EL ELEMENTO [" + wsReturn + "] NO FUE ENCONTRADO EN LA RESPUESTA SOAP");
				
				return respuesta.getTextContent();
			} catch (Exception ex) {
				if(ex instanceof AutenticacionException)
					throw (AutenticacionException)ex;
				throw new AutenticacionException("LA RESPUESTA NO PUDO SER PROCESADA. " + ex.getMessage());
			}
			
		} catch (IOException ex) {
			throw new AutenticacionException("ERROR AL EJECUTAR PETICION SOAP. " + ex.getMessage());
		} finally {
			if(http != null) http.disconnect();
			try { is.close(); } catch(Exception ex) {}
		}
	}
	
	private static void NoValidarSSL(HttpsURLConnection https) throws NoSuchAlgorithmException, KeyManagementException {
		if(SSLSocketFactory == null) {
			HostnameVerifier = new HostnameVerifier() {
				@Override
				public boolean verify(String urlHostName, SSLSession session) {
                    return true;
                }
			};
			
			final TrustManager[] trustAllCerts = new TrustManager[]{
				new X509TrustManager() {
					
					@Override
					public X509Certificate[] getAcceptedIssuers() {
						return null;
					}
					
					@Override
					public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException { }
					
					@Override
					public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException { }
				}
			};
			final SSLContext sslContext = SSLContext.getInstance("SSL");
			sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
			SSLSocketFactory 			= sslContext.getSocketFactory();
		}
		https.setSSLSocketFactory(SSLSocketFactory);
		https.setHostnameVerifier(HostnameVerifier);
	}

	private static Document StreamToDom(InputStream is) throws SAXException, IOException, ParserConfigurationException {
		return DOCUMENT_BUILDER_FACTORY
				.newDocumentBuilder()
				.parse(is);
	}
	
	private static Document StringToDom(String xml) throws SAXException, IOException, ParserConfigurationException {
		StringReader sr = new StringReader(xml);
		InputSource is  = new InputSource(sr);
		try {
			return DOCUMENT_BUILDER_FACTORY
					.newDocumentBuilder()
					.parse(is);
		} finally {
			sr.close();
		}
	}

	private static String DomToString(Document dom) throws TransformerFactoryConfigurationError, TransformerException, IOException {
		StringWriter sWriter	= new StringWriter();
		try {
	        Transformer serializer 	= TransformerFactory.newInstance().newTransformer();
	        DOMSource domSource		= new DOMSource(dom);
	        StreamResult sresult	= new StreamResult(sWriter);
	        serializer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
	        serializer.setOutputProperty(OutputKeys.INDENT, "no");
	        serializer.setOutputProperty(OutputKeys.ENCODING, "ISO-8859-1");
	        serializer.setOutputProperty(OutputKeys.VERSION, "1.0");
	        serializer.transform(domSource, sresult);
		} finally {
			sWriter.close();
		}	        
        return sWriter.toString();
	}
	
	private static Node GetNode(Element ele, String tag) {
		NodeList nl = ele.getElementsByTagName(tag);
		if(nl.getLength() == 0)
			return null;
		return nl.item(0);
	}
}
