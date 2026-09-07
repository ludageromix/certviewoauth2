package com.portagecybertech.certviewoauth2.authorizationserver;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest 
@AutoConfigureMockMvc 
class PingControllerTest {
    
    @Autowired 
    private MockMvc mockMvc;

    @Test 
    void repondPongSurLeEndpointPing() throws Exception {
        mockMvc.perform(get("/ping"))
            .andExpect(status().isOk())
            .andExpect(content().string("pong"));
    }
}
