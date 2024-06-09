package com.spring.security.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/private")
@RequiredArgsConstructor
public class PrivateController {

    @GetMapping("/get")
    public String examplePrivate() {
        return "Hello, authorized user!";
    }
}
