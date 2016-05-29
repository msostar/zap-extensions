package org.zaproxy.zap.extension.asvspscan.SessionManagement;

import net.htmlparser.jericho.Source;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

import java.util.Vector;

/**
 * Created by msostar on 10.5.2016..
 */
public class DomainTag extends PluginPassiveScanner {

  //  private static Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_20");
    private PassiveScanThread parent = null;
    private static final Logger logger = Logger.getLogger(DomainTag.class);
    private String DomainDesc="When no domain is set in the cookie, the cookie should only match the exact host name of the request. No sub domains, no partial matches. This means simply not including the domain attribute – it is not valid to set an empty domain attribute. Unfortunately, Internet Explorer appears to treat this as the host name along with any subdomains.\n" +
            "When setting a domain in the cookie, the safe choice is to have it preceded by a dot, like .erik.io. The cookie will match with all sub domains.\n" +
            "Setting a cookie domain without a preceding dot, like erik.io, is invalid in RFC 2109 implementations, and will produce the same behaviour as with a preceding dot on other implementations. There is no way to restrict a cookie to a specific explicitly set domain, without sub domains being included.";



    @Override
    public void scanHttpRequestSend(HttpMessage httpMessage, int i) {

    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {


        long start = System.currentTimeMillis();

        Vector<String> cookies1 = msg.getResponseHeader().getHeaders(HttpHeader.SET_COOKIE);


        if (cookies1 != null) {
            for (String cookie : cookies1) {
                if (cookie.toLowerCase().contains("domain")) {

                    int domainValue1= cookie.toLowerCase().lastIndexOf("domain")+ 7;
                    int domainValue2= cookie.toLowerCase().indexOf(";", domainValue1+1);
                    if(domainValue2==-1){
                        domainValue2= cookie.toLowerCase().indexOf(" ", domainValue1+1);
                        if(domainValue2==-1){
                            domainValue2= cookie.toLowerCase().length();
                        }
                    }

                    String proba= cookie.substring(domainValue1, domainValue2);

                    if(proba.toLowerCase().indexOf(".")<2){

                        System.out.println("1.  "+ proba);

                        Alert alert = new Alert(getPluginId(), Alert.RISK_INFO, Alert.CONFIDENCE_MEDIUM, getName());
                        alert.setDetail(
                                "Domain is maybe set too loosely",
                                msg.getRequestHeader().getURI().toString(),
                                "",    // Param
                                "", // Attack
                                DomainDesc, // Other info
                                "Re-evaluate whether subdomains can set and use cookies",
                                "http://erik.io/blog/2014/03/04/definitive-guide-to-cookie-domains/\n" + "https://www.owasp.org/index.php/Testing_for_cookies_attributes_(OTG-SESS-002)",
                                "",    // Evidence
                                0,    // CWE Id
                                0,    // WASC Id
                                msg);

                        parent.raiseAlert(id, alert);

                    }

                    if(proba.toLowerCase().indexOf(".")>1){


                        System.out.println("2.  "+ proba);

                        Alert alert = new Alert(getPluginId(), Alert.RISK_INFO, Alert.CONFIDENCE_MEDIUM, getName());
                        alert.setDetail(
                                "Domain is deprecated",
                                msg.getRequestHeader().getURI().toString(),
                                "",    // Param
                                "", // Attack
                                DomainDesc, // Other info
                                "Domain must contain \" . \" at the beginning",
                                "http://erik.io/blog/2014/03/04/definitive-guide-to-cookie-domains/\n" + "https://www.owasp.org/index.php/Testing_for_cookies_attributes_(OTG-SESS-002)",
                                "",    // Evidence
                                0,    // CWE Id
                                0,    // WASC Id
                                msg);

                        parent.raiseAlert(id, alert);

                    }



                }else {

                    System.out.println("3.  ");

                    Alert alert = new Alert(getPluginId(), Alert.RISK_INFO, Alert.CONFIDENCE_MEDIUM, getName());
                    alert.setDetail(
                            "Domain is maybe set too strictly",
                            msg.getRequestHeader().getURI().toString(),
                            "",    // Param
                            "", // Attack
                            DomainDesc, // Other info
                            "Domain tag isn't set. Cookies can't be used by subdomains",
                            "http://erik.io/blog/2014/03/04/definitive-guide-to-cookie-domains/\n" + "https://www.owasp.org/index.php/Testing_for_cookies_attributes_(OTG-SESS-002)",
                            "",    // Evidence
                            0,    // CWE Id
                            0,    // WASC Id
                            msg);

                    parent.raiseAlert(id, alert);

                }
            }
        }



        if (logger.isDebugEnabled()) {
            logger.debug("\tScan of record " + id + " took " + (System.currentTimeMillis() - start) + " ms");
        }

    }

    @Override
    public void setParent(PassiveScanThread parent) {
        this.parent = parent;
    }


    @Override
    public int getPluginId() {
		/*
		 * This should be unique across all active and passive rules.
		 * The master list is https://github.com/zaproxy/zaproxy/blob/develop/src/doc/alerts.xml
		 */
        return 10107;
    }

    @Override
    public String getName() {
        // Strip off the "Example Passive Scanner: " part if implementing a real one ;)
        /*
        if (vuln != null) {
            return "Example Passive Scanner: " + vuln.getAlert();
        }
        */
        return "Cookie: Domain is maybe set wrong ";
    }

}
