/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package dhclient;

import java.net.*;
import java.io.*;
import java.util.Scanner;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import dhserver.DHKE;
import java.math.BigInteger;

/**
 *
 * @author
 */
public class DHClient {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        try {
            Socket s = new Socket("localhost", 12345);
            PrintWriter pw = new PrintWriter(s.getOutputStream(), true);
            BufferedReader bf = new BufferedReader(new InputStreamReader(s.getInputStream()));
            
            String str = "";
            
            pw.println("ke");
            str = bf.readLine();
            String p = str;
            str = bf.readLine();
            String g = str;

            DHKE dh = new DHKE(new BigInteger(p), new BigInteger(g), 1024);
            
            System.out.println("Prime: " + p);
            System.out.println("Base: " + g);
            
            String pkey = "";
            str = bf.readLine();
            while(!str.equals("key end")){
                pkey = pkey + str;
                str = bf.readLine();
            };
            str = pkey;
            System.out.println("Server PublicKey: " + str);
            BASE64Decoder decoder = new BASE64Decoder();
            byte[] publicKey = decoder.decodeBuffer(str);
            dh.generateSecretKey(publicKey, "DES");
            
            publicKey = dh.getPublicKeyBytes();
            BASE64Encoder encoder = new BASE64Encoder();
            pw.println(encoder.encode(publicKey));
            
            pw.println("key end");
            
            System.out.println("Key agreement end");

            str = dh.encrypt("Safe message");
            pw.println(str);

            str = bf.readLine();
            System.out.println("Encrypted message from server: "+str);
            str = dh.decrypt(str);
            System.out.println("Decrypted messge: "+str);
            
            pw.close();
            bf.close();
        } catch (Exception e) {
            System.out.println("Exception: "+e.getMessage());
        }
    }
    
}
