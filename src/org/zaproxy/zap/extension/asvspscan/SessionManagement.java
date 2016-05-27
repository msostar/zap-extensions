package org.zaproxy.zap.extension.asvspscan;

import net.htmlparser.jericho.Source;
import org.apache.log4j.Logger;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;

import java.net.HttpCookie;
import java.util.List;
import java.util.TreeSet;
import java.util.Vector;

/**
 * Created by msostar on 10.5.2016..
 */
public class SessionManagement extends PluginPassiveScanner {

    private static Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_20");
    private PassiveScanThread parent = null;
    private static final Logger logger = Logger.getLogger(SessionManagement.class);



    @Override
    public void scanHttpRequestSend(HttpMessage httpMessage, int i) {

    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {

        long start = System.currentTimeMillis();

        Vector<String> cookies1 = msg.getResponseHeader().getHeaders(HttpHeader.SET_COOKIE);

        if (cookies1 != null) {
            for (String cookie : cookies1) {
                if (cookie.toLowerCase().indexOf("secure") < 0) {
                    //this.raiseAlert(msg, id, cookie);
                }
            }
        }

        Vector<String> cookies2 = msg.getResponseHeader().getHeaders(HttpHeader.SET_COOKIE2);

        if (cookies2 != null) {
            for (String cookie : cookies2) {
                if (cookie.toLowerCase().indexOf("secure") < 0) {
                    //this.raiseAlert(msg, id, cookie);
                }
            }
        }



        Alert alert = new Alert(getPluginId(), Alert.RISK_HIGH, Alert.CONFIDENCE_HIGH, getName());
        alert.setDetail(
                getDescription(),
                msg.getRequestHeader().getURI().toString(),
                "ovo",	// Param
                " mi je ", // Attack
                "skola", // Other info
                getSolution(),
                getReference(),
                "",	// Evidence
                0,	// CWE Id
                0,	// WASC Id
                msg);

        parent.raiseAlert(id, alert);

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
        return 10010;
    }

    @Override
    public String getName() {
        // Strip off the "Example Passive Scanner: " part if implementing a real one ;)
        if (vuln != null) {
            return "Example Passive Scanner: " + vuln.getAlert();
        }
        return "Example Passive Scanner: Denial of Service";
    }

    public String getDescription() {
        if (vuln != null) {
            return vuln.getDescription();
        }
        return "Failed to load vulnerability description from file";
    }

    public int getCategory() {
        return Category.MISC;
    }

    public String getSolution() {
        if (vuln != null) {
            return vuln.getSolution();
        }
        return "Failed to load vulnerability solution from file";
    }

    public String getReference() {
        if (vuln != null) {
            StringBuilder sb = new StringBuilder();
            for (String ref : vuln.getReferences()) {
                if (sb.length() > 0) {
                    sb.append("\n");
                }
                sb.append(ref);
            }
            return sb.toString();
        }
        return "Failed to load vulnerability reference from file";
    }
}
