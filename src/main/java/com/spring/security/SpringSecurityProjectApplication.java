package com.spring.security;

import com.spring.security.entity.Role;
import com.spring.security.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@RequiredArgsConstructor
public class SpringSecurityProjectApplication implements CommandLineRunner {

	private final RoleRepository roleRepository;

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityProjectApplication.class, args);
	}

	@Override
	public void run(String... args) {
		Role role=new Role(1L,"USER");
		roleRepository.save(role);
		role.setId(2L);
		role.setName("ADMIN");
		roleRepository.save(role);
	}

}
