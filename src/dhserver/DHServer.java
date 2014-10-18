/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package dhserver;

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
public class DHServer {
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        try{
            DHKE dh = new DHKE(1024);
            String p = dh.p.toString();
            String g = dh.g.toString();
            System.out.println("Prime: " + p);
            System.out.println("Base: " + g);
            
            ServerSocket server = new ServerSocket(12345);
            Socket sock = server.accept();
        
            System.out.println("Client connected...");
        
            PrintWriter pw  = new PrintWriter(sock.getOutputStream(), true);//outcoming msg
            BufferedReader bf = new BufferedReader(new InputStreamReader(sock.getInputStream()));//incoming msg
            
            String str= "";
            byte[] publicKey = dh.getPublicKeyBytes();
            BASE64Encoder encoder = new BASE64Encoder();
            
            str = bf.readLine();
            while(!str.equals("ke")) str = bf.readLine();
            pw.println(p);
            pw.println(g);
            pw.println(encoder.encode(publicKey));
            pw.println("key end");
            
            String pkey = "";
            str = bf.readLine();
            while(!str.equals("key end")){
                pkey = pkey + str;
                str = bf.readLine();
            };
            str = pkey;
            System.out.println("Client PublicKey: " + str);
            BASE64Decoder decoder = new BASE64Decoder();
            publicKey = decoder.decodeBuffer(str);
            dh.generateSecretKey(publicKey, "DES");
            
            System.out.println("Key agreement end");
            
            str = bf.readLine();
            System.out.println("Encrypted message from client: "+str);
            str = dh.decrypt(str);
            System.out.println("Decrypted message: "+str);
            str = dh.encrypt("This is response message from server");
            pw.println(str);
            
            pw.close();
            bf.close();
        }
        catch(Exception e){
            System.out.println("Exception: "+e.getMessage());
        }
    }    
}
