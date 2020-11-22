package com.cos.security2.controller;

import com.cos.security2.model.RoleType;
import com.cos.security2.model.User;
import com.cos.security2.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
public class RestApiController {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    @GetMapping({"/", ""})
    public String home() {

        return "<h1>home</h1>";
    }

    @PostMapping("/token")
    public String token() {

        return "<h1>token</h1>";
    }

    @PostMapping("join")
    public String join(@RequestBody User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setRole(RoleType.USER);
        userRepository.save(user);
        return "회원가입 완료";
    }

    // user, manager, admin 권한 접근 가능
    @GetMapping("/api/v1/user")
    public String user() {
        return "user";
    }

    // user, manager 권한 접근 가능
    @GetMapping("/api/v1/manager")
    public String manager() {
        return "manager";
    }

    // admin 권한 접근 가능
    @GetMapping("/api/v1/admin")
    public String admin() {
        return "admin";
    }

}
