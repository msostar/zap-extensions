package org.zaproxy.zap.extension.asvspscan.SessionManagement;

import net.htmlparser.jericho.Source;
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
public class SecureCookieTag extends PluginPassiveScanner {

  //  private static Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_20");
    private PassiveScanThread parent = null;
    private static final Logger logger = Logger.getLogger(SecureCookieTag.class);



    @Override
    public void scanHttpRequestSend(HttpMessage httpMessage, int i) {

    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {

        long start = System.currentTimeMillis();

        Vector<String> cookies1 = msg.getResponseHeader().getHeaders(HttpHeader.SET_COOKIE);

        if (cookies1 != null) {
            for (String cookie : cookies1) {


                if (cookie.toLowerCase().contains("secure")) {
                    break;

                }else {

                    Alert alert = new Alert(getPluginId(), Alert.RISK_MEDIUM, Alert.CONFIDENCE_HIGH, getName());
                    alert.setDetail(
                            "Secure flag isn't turned on",
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

        Vector<String> cookies2 = msg.getResponseHeader().getHeaders(HttpHeader.SET_COOKIE2);

        if (cookies2 != null) {
            for (String cookie : cookies2) {
                if (cookie.toLowerCase().contains("secure")) {

                    break;

                }else {

                    Alert alert = new Alert(getPluginId(), Alert.RISK_MEDIUM, Alert.CONFIDENCE_HIGH, getName());
                    alert.setDetail(
                            "Secure flag isn't turned on",
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
        return 10011;
    }

    @Override
    public String getName() {
        // Strip off the "Example Passive Scanner: " part if implementing a real one ;)
        /*
        if (vuln != null) {
            return "Example Passive Scanner: " + vuln.getAlert();
        }
        */
        return "Cookie: Set Secure Tag";
    }

}
