package com.portagecybertech.certviewoauth2.authorizationserver;

import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;


@RestController 
class PingController {
    
    @GetMapping("/ping")
    String ping() {
        return "pong";
    }
    
}
