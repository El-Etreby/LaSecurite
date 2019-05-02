package com.socket;

import java.io.Serializable;
import java.security.PublicKey;

public class Message implements Serializable{
    
    private static final long serialVersionUID = 1L;
    public String type, sender, content, recipient, dh, HMAC;
    public PublicKey  pmKey;

   
    public Message(String type, String sender, String content, String recipient, String dh, PublicKey  pmKey, String HMAC){
    
        this.type = type; this.sender = sender; this.content = content; this.recipient = recipient; this.dh = dh;
        this.pmKey=pmKey; this.HMAC = HMAC;
    }
    
    @Override
    public String toString(){
        return "{type='"+type+"', sender='"+sender+"', content='"+content+"', recipient='"+recipient+"', DH='"+dh+"',HMAC='"+HMAC+"'}";
    }
}
