package org.zaproxy.zap.extension.asvspscan.Authentication;

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
public class PasswordEcho extends PluginPassiveScanner {

  //  private static Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_20");
    private PassiveScanThread parent = null;
    private static final Logger logger = Logger.getLogger(PasswordEcho.class);



    @Override
    public void scanHttpRequestSend(HttpMessage httpMessage, int i) {

        String body= httpMessage.getRequestBody().toString();
        System.out.println(body);

    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {

        long start = System.currentTimeMillis();

        Vector<String> cookies1 = msg.getResponseHeader().getHeaders(HttpHeader.SET_COOKIE);




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
        return 10012;
    }

    @Override
    public String getName() {
        // Strip off the "Example Passive Scanner: " part if implementing a real one ;)
        /*
        if (vuln != null) {
            return "Example Passive Scanner: " + vuln.getAlert();
        }
        */
        return "Password is echoed on web page";
    }

}
