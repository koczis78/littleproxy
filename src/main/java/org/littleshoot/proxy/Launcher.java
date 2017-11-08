package org.littleshoot.proxy;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.*;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.PosixParser;
import org.apache.commons.cli.UnrecognizedOptionException;
import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.xml.DOMConfigurator;
import org.littleshoot.proxy.extras.SelfSignedMitmManager;
import org.littleshoot.proxy.impl.DefaultHttpProxyServer;
import org.littleshoot.proxy.impl.ProxyUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Map;

/**
 * Launches a new HTTP proxy.
 */
public class Launcher {

    private static final Logger LOG = LoggerFactory.getLogger(Launcher.class);

    private static final String OPTION_DNSSEC = "dnssec";

    private static final String OPTION_PORT = "port";

    private static final String OPTION_HELP = "help";

    private static final String OPTION_MITM = "mitm";

    private static final String OPTION_NIC = "nic";

    /**
     * Starts the proxy from the command line.
     * 
     * @param args
     *            Any command line arguments.
     */
    public static void main(final String... args) {
        pollLog4JConfigurationFileIfAvailable();
        LOG.info("Running LittleProxy with args: {}", Arrays.asList(args));
        final Options options = new Options();
        options.addOption(null, OPTION_DNSSEC, true,
                "Request and verify DNSSEC signatures.");
        options.addOption(null, OPTION_PORT, true, "Run on the specified port.");
        options.addOption(null, OPTION_NIC, true, "Run on a specified Nic");
        options.addOption(null, OPTION_HELP, false,
                "Display command line help.");
        options.addOption(null, OPTION_MITM, false, "Run as man in the middle.");
        
        final CommandLineParser parser = new PosixParser();
        final CommandLine cmd;
        try {
            cmd = parser.parse(options, args);
            if (cmd.getArgs().length > 0) {
                throw new UnrecognizedOptionException(
                        "Extra arguments were provided in "
                                + Arrays.asList(args));
            }
        } catch (final ParseException e) {
            printHelp(options,
                    "Could not parse command line: " + Arrays.asList(args));
            return;
        }
        if (cmd.hasOption(OPTION_HELP)) {
            printHelp(options, null);
            return;
        }
        final int defaultPort = 8080;
        int port;
        if (cmd.hasOption(OPTION_PORT)) {
            final String val = cmd.getOptionValue(OPTION_PORT);
            try {
                port = Integer.parseInt(val);
            } catch (final NumberFormatException e) {
                printHelp(options, "Unexpected port " + val);
                return;
            }
        } else {
            port = defaultPort;
        }


        System.out.println("About to start server on port: " + port);
        HttpProxyServerBootstrap bootstrap = DefaultHttpProxyServer
                .bootstrapFromFile("./littleproxy.properties")
                .withPort(port)
                .withAllowLocalOnly(false);

        if (cmd.hasOption(OPTION_NIC)) {
            final String val = cmd.getOptionValue(OPTION_NIC);
            bootstrap.withNetworkInterface(new InetSocketAddress(val, 0));
        }

        if (cmd.hasOption(OPTION_MITM)) {
            LOG.info("Running as Man in the Middle");
            bootstrap.withManInTheMiddle(new SelfSignedMitmManager());
        }
        
        if (cmd.hasOption(OPTION_DNSSEC)) {
            final String val = cmd.getOptionValue(OPTION_DNSSEC);
            if (ProxyUtils.isTrue(val)) {
                LOG.info("Using DNSSEC");
                bootstrap.withUseDnsSec(true);
            } else if (ProxyUtils.isFalse(val)) {
                LOG.info("Not using DNSSEC");
                bootstrap.withUseDnsSec(false);
            } else {
                printHelp(options, "Unexpected value for " + OPTION_DNSSEC
                        + "=:" + val);
                return;
            }
        }

        bootstrap.withFiltersSource(new HttpFiltersSourceAdapter() {

            public HttpFilters filterRequest(HttpRequest originalRequest, ChannelHandlerContext ctx) {

                return new HttpFiltersAdapter(originalRequest) {
                    @Override
                    public HttpResponse clientToProxyRequest(HttpObject httpObject) {
                        System.out.println("requestPre: " + originalRequest.getMethod() + " " + originalRequest.getUri());

                        if(!originalRequest.getUri().contains("success.txt") && !originalRequest.getUri().contains("firefox")){
                            System.out.println("no empeded firefox request");
                        }


                        if(httpObject instanceof HttpRequest) {
                            HttpRequest req = ((HttpRequest)httpObject);

                            String newUri = req.getUri();
                            if("CONNECT".equalsIgnoreCase(originalRequest.getMethod().name())) {
                                System.out.println("CONNECT method");

                                //send to remote ff
                                try {
                                    Socket ffRemoteSocket = new Socket("192.168.56.1", 32000);
                                    DataOutputStream outputStream = new DataOutputStream(ffRemoteSocket.getOutputStream());
                                    BufferedReader inFromFf = new BufferedReader(new InputStreamReader(ffRemoteSocket.getInputStream()));

                                    String remoteUri = "window.location=\"http://" + req.getUri() + "\"";
                                    outputStream.writeBytes(remoteUri);

                                    String resp = inFromFf.readLine();

                                    System.out.println("response from FF: " + resp);


                                } catch (Exception e) {
                                    e.printStackTrace();
                                }
                                //end


                                newUri = "192.168.56.1:6080";
                            } else {
                                String orgUri = req.getUri();
                                //String newUri = "http://localhost:9082/sls/protected/login/login.jsp";
                                //String newUri = "http://localhost:6080/vnc_lite.html";

                                try {
                                    URL url = new URL(orgUri);

                                    String protocol = url.getProtocol();
                                    String userInfo = url.getUserInfo();
                                    String authority = url.getAuthority();
                                    String host = url.getHost();
                                    int port = url.getPort();
                                    String path = url.getPath();
                                    String query = url.getQuery();
                                    String ref = url.getRef();

                                    //   http://onet.pl/vnc_lite.html?host=localhost&port=6080

                                    //String newUri =

                                    //String newUri = orgUri.replace("onet.pl", "192.168.56.1:6080");
                                    //newUri = newUri + "/vnc_lite.html?host=192.168.56.1&port=6080";

                                    newUri = protocol + "://192.168.56.1:6080";

                                    if (path.equalsIgnoreCase("/") || path.equalsIgnoreCase("")) {
                                        path = "/vnc_lite.html?host=192.168.56.1&port=6080";
                                    }

                                    newUri += path;
                                } catch (MalformedURLException e) {
                                    e.printStackTrace();
                                }
                            }

                            System.out.println("HEADERS BEFORE CHANGE");
                            boolean isRef = false;
                            for (Map.Entry<String, String> header : req.headers()) {
                                System.out.println("key: " + header.getKey() + ", value: " + header.getValue());
                                if("Referer".equalsIgnoreCase(header.getKey())) {
                                    isRef = true;
                                }
                            }

                            if(isRef) {
                                req.headers().remove("Referer");
                                req.headers().add("Referer", "http://192.168.56.1:6080/");
                            }

                            req.headers().remove("Host");
                            req.headers().add("Host", "192.168.56.1:6080");

                            System.out.println("HEADERS AFTER CHANGE");
                            for (Map.Entry<String, String> header : req.headers()) {
                                System.out.println("key: " + header.getKey() + ", value: " + header.getValue());
                            }

                            req.setUri(newUri);


                        }

                        if(httpObject instanceof HttpContent)
                        {
                            System.out.println((((HttpContent) httpObject)
                                    .content().toString(
                                            Charset.forName("UTF-8"))));
                        }

                        return super.clientToProxyRequest(httpObject);
                    }

                    @Override
                    public HttpResponse proxyToServerRequest(HttpObject httpObject) {

                        System.out.println("httpObject: " + httpObject);


                        return null;
                    }

                    @Override
                    public HttpObject proxyToClientResponse(HttpObject httpObject) {
                        System.out.println("proxyToClientResponse: " + httpObject);

                        if(httpObject instanceof HttpResponse) {

            /*HttpResponse res = (HttpResponse)httpObject;

            res.setStatus(HttpResponseStatus.FOUND);

            res.headers().add("Location", "http://localhost:9082/sls/protected/login/login.jsp");

            return res;*/
                        }

                        if (httpObject instanceof HttpContent) {
                            String content = (((HttpContent) httpObject)
                                    .content().toString(
                                            Charset.forName("UTF-8")));
                            System.out.println("oldContent" + content);






                            //String newContent = "<html><body><h1>It works! HAHAAHAHAH</h1></body></html>\n";
            /*try {
                Path path = Paths.get("/opt/_projekty/_2manybytes/noVNC/vnc_lite.html");
                byte[] data = Files.readAllBytes(path);

                ByteBuf newBuf = Unpooled.buffer(data.length);
                newBuf.writeBytes(data);

                HttpContent newResponse = ((HttpContent) httpObject).copy();
                newResponse.content().clear().writeBytes(newBuf);
                return newResponse;

            } catch (IOException e) {
                System.out.println("Cannot read file");
            }*/

                        }

                        HttpObject ret = super.proxyToClientResponse(httpObject);

                        return ret;
                    }

       /* @Override
        public HttpResponse requestPost(HttpObject httpObject) {
            return null;
        }

        @Override
        public HttpObject responsePre(HttpObject httpObject) {
            if (httpObject instanceof HttpResponse) {

            } else if (httpObject instanceof HttpContent) {
                System.out.println((((HttpContent) httpObject)
                        .content().toString(
                                Charset.forName("UTF-8"))));
            }
            return httpObject;
        }

        @Override
        public HttpObject responsePost(HttpObject httpObject) {
            // TODO: implement your filtering here
            return httpObject;
        }*/
                };
            }

        });






        System.out.println("About to start...");
        bootstrap.start();
    }

    private static void printHelp(final Options options,
            final String errorMessage) {
        if (!StringUtils.isBlank(errorMessage)) {
            LOG.error(errorMessage);
            System.err.println(errorMessage);
        }

        final HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp("littleproxy", options);
    }

    private static void pollLog4JConfigurationFileIfAvailable() {
        File log4jConfigurationFile = new File("src/test/resources/log4j.xml");
        if (log4jConfigurationFile.exists()) {
            DOMConfigurator.configureAndWatch(
                    log4jConfigurationFile.getAbsolutePath(), 15);
        }
    }
}
