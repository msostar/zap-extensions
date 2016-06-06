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
    private String request="abcdefgijkl";



    @Override
    public void scanHttpRequestSend(HttpMessage httpMessage, int i) {

        String body= httpMessage.getRequestBody().toString();
        String[] bodyParts= body.split("=");
        int counter=0;
        for(String bdy: bodyParts){
            if(bdy.contains("pass") || bdy.contains("psw")){
                request=bodyParts[counter+1];
                break;
            }
            counter++;
        }
        request=request.split("&")[0];

        System.out.println(request);




    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {



        String body= msg.getResponseBody().toString();
        if(body.contains(request)){

            Alert alert = new Alert(getPluginId(), Alert.RISK_LOW, Alert.CONFIDENCE_HIGH, getName());
            alert.setDetail(
                    "Password is echoed on web page",
                    msg.getRequestHeader().getURI().toString(),
                    "password",    // Param
                    "", // Attack
                    "", // Other info
                    "Change password (password is to weak,to generic or same as username) and check why does it echo on the web page",
                    "https://www.youtube.com/watch?v=zUM7i8fsf0g\n" +
                            "https://ckarande.gitbooks.io/owasp-nodegoat-tutorial/content/tutorial/a2_-_password_guessing_attack.html",
                    "",    // Evidence
                    0,    // CWE Id
                    0,    // WASC Id
                    msg);

            parent.raiseAlert(id, alert);
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
