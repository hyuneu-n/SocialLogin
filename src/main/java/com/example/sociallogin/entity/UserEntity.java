package com.example.sociallogin.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import org.springframework.data.annotation.CreatedDate;

import java.time.LocalDate;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@Entity(name= "user") //자카르타
@Table(name = "user")
public class UserEntity {
    @Id
    @Column(name="user_id")
    private String userId;
    @Column(name = "user_name")
    private String userName;
    @Column(name = "user_email")
    private String userEmail;
    @Column(name = "user_login_type")
    private String userLoginType;
    @Column(name = "user_role")
    private String userRole;
    @Column(name = "createdAt")
    @CreatedDate
    private LocalDate createdAt;

    public UserEntity(String userId, String userName,
                      String userEmail, String userLoginType,
                      String userRole) {
        this.userId = userId;
        this.userName = userName;
        this.userEmail = userEmail;
        this.userLoginType = userLoginType;
        this.userRole = userRole;
    }

}
