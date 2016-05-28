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

                    URI url = msg.getRequestHeader().getURI();
                    String shortURL="";
                    try {
                        shortURL= url.getHost().toLowerCase().toString();

                    } catch (URIException e) {
                        e.printStackTrace();
                    }

                    int bla= cookie.toLowerCase().lastIndexOf("domain")+ 7;
                    int bla2= cookie.toLowerCase().indexOf(" ", bla+10);

                    if(bla2==-1){
                        bla2= cookie.toLowerCase().indexOf(";", bla+10);
                        System.out.println(bla + "blaaaa111" + bla2);

                        if(bla2==-1){
                            bla2= cookie.toLowerCase().length();
                            System.out.println(bla + "blaaaa222" + bla2);

                        }
                    }
                    System.out.println(cookie.toLowerCase());

                    System.out.println(bla + "blaaaa" + bla2);

                    String proba= cookie.substring(bla, bla2);

                    System.out.println(proba + "blaaaa");

                }else {

                    Alert alert = new Alert(getPluginId(), Alert.RISK_INFO, Alert.CONFIDENCE_MEDIUM, getName());
                    alert.setDetail(
                            "Domain is set too loosely",
                            msg.getRequestHeader().getURI().toString(),
                            "",    // Param
                            "", // Attack
                            "", // Other info
                            "Set secure flag in cookie",
                            "https://www.owasp.org/index.php/SecureFlag",
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
        return "Cookie: Domain is set too loosely ";
    }

}
