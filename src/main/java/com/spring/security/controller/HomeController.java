package com.spring.security.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.security.Principal;


@Controller
@RequestMapping("/home")
public class HomeController {

    @GetMapping("/index")
    public String hello(Principal principal,Model model) {
     //   public String hello(Model model) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        System.out.println(principal.getName());
        model.addAttribute("authentication", authentication);
        System.out.println(model.getAttribute("email"));
        System.out.println(principal);
        System.out.println(model);
        return "home";
    }

}
