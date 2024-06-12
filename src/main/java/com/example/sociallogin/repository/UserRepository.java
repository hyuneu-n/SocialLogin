package com.example.sociallogin.repository;

import com.example.sociallogin.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<UserEntity, String> {
//<>안에 들어가는 요소 Entity이름, Entity의 PK type 디폴트가 User와 Long으로 되어있지?
//근데 우리는 UserEntity로 이름을 만들었고 PK가 String이니까
//<>안에 들어가는 요소를 바꿔줌
UserEntity findByUserId(String userId);
}