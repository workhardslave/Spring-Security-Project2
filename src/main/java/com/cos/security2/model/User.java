package com.cos.security2.model;

import lombok.Data;
import lombok.Getter;

import javax.persistence.*;

@Data
@Entity
public class User {

    @Id // PK
    @GeneratedValue(strategy = GenerationType.IDENTITY) // 프로젝트에서 연결된 DB의 넘버링 전략을 따라감
    private int id; // sequence, auto_increment

    private String email;

    private String password;

    private String username;

    @Enumerated(EnumType.STRING)
    private RoleType role; // USER, MANAGER, ADMIN

    public String getRoleValue() {
        return this.role.getValue();
    }
}
