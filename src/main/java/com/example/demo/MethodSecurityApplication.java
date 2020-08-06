package com.example.demo;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import javax.annotation.security.RolesAllowed;
import javax.persistence.CascadeType;
import javax.persistence.Entity;
import javax.persistence.EntityListeners;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.OneToOne;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.annotation.CreatedBy;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedBy;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.domain.AuditorAware;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.data.repository.query.SecurityEvaluationContextExtension;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.ToString;

@EnableJpaAuditing
@EnableGlobalMethodSecurity(prePostEnabled = true, jsr250Enabled = true, securedEnabled = true)
@SpringBootApplication
public class MethodSecurityApplication {

	@Bean
	SecurityEvaluationContextExtension securityEvaluationContextExtension() {
		return new SecurityEvaluationContextExtension();
	}
	
	@Bean
	AuditorAware<String> auditor() {
		return () -> {
			SecurityContext context = SecurityContextHolder.getContext();
			Authentication authentication = context.getAuthentication();
			if (null != authentication) {
				return Optional.ofNullable(authentication.getName());
			}
			return Optional.empty();
		};
	}
	
	public static void main(String[] args) {
		SpringApplication.run(MethodSecurityApplication.class, args);
	}

}

@Configuration
@EnableWebSecurity
class SecurityConfiguration extends WebSecurityConfigurerAdapter {
	
	// FilterChainProxy is main entry class for Spring Security

		@Override
		protected void configure(HttpSecurity http) throws Exception {
				
				http
	                .authorizeRequests().antMatchers("/console/**").permitAll();
				
				http.csrf().disable();
				http.headers().frameOptions().disable();
		}
}

@Transactional
@Component
class Runner implements ApplicationRunner {

	private final UserRepository userRepository;

	private final AuthorityRepository authorityRepository;

	private final MessageRepository messageRepository;
	
	private final UserDetailsService userDetailsService;
	
	Runner(UserRepository userRepository, AuthorityRepository authorityRepository,
			MessageRepository messageRepository, UserDetailsService userDetailsService) {
		this.userRepository = userRepository;
		this.authorityRepository = authorityRepository;
		this.messageRepository = messageRepository;
		this.userDetailsService = userDetailsService;
		
	}
	
	private void authenticate(String username) {
		UserDetails user = this.userDetailsService.loadUserByUsername(username);
		Authentication authentication = new UsernamePasswordAuthenticationToken(user,
				user.getPassword(), user.getAuthorities());
		SecurityContextHolder.getContext().setAuthentication(authentication);
	}

	@Override
	public void run(ApplicationArguments args) throws Exception {
		
		Authority user = this.authorityRepository.save(new Authority("USER"));
		Authority admin = this.authorityRepository.save(new Authority("ADMIN"));
		
		User akash = this.userRepository.save(new User("akash", "password", user,admin));
		User shikha = this.userRepository.save(new User("shikha", "password", user));
		
		Message messageForAkash = this.messageRepository.save(new Message("hi Akash!!", akash));
		this.messageRepository.save(new Message("Hi 1*", akash));
		this.messageRepository.save(new Message("Hi 2*", akash));

		this.messageRepository.save(new Message("Hi 1**", shikha));

		
		System.out.println("akash:: " + akash.toString());
		System.out.println("shikha:: " + shikha.toString());
		
		attempAccess(akash.getEmail(), shikha.getEmail(), messageForAkash.getId(),
				(id) -> this.messageRepository.findByIdRolesAllowed(id));

		attempAccess(akash.getEmail(), shikha.getEmail(), messageForAkash.getId(),
				(id) -> this.messageRepository.findByIdSecured(id));
		
		attempAccess(akash.getEmail(), shikha.getEmail(), messageForAkash.getId(),
				this.messageRepository::findByIdPreAuthorized);
		
		attempAccess(akash.getEmail(), shikha.getEmail(), messageForAkash.getId(),
				this.messageRepository::findByIdPostAuthorized);
		
		authenticate(akash.getEmail());
		this.messageRepository.findMessagesFor(PageRequest.of(0, 5)).forEach(System.out::println);

		authenticate(shikha.getEmail());
		this.messageRepository.findMessagesFor(PageRequest.of(0, 5)).forEach(System.out::println);

		System.out.println(this.messageRepository.save(new Message("Audited msg", akash)));
		
	}
	
	private void attempAccess(String adminUser, String regularUser, Long msgId, Function<Long, Message> fn) {
		authenticate(adminUser);	
		System.out.println("Result for "+adminUser+" :: "+fn.apply(msgId));
		
		try {
			authenticate(regularUser);		
			System.out.println("Result for "+regularUser+" :: "+fn.apply(msgId));
		} catch (Exception e) {
			System.out.println("Error :: Couldn't get result for shikha");
		}
	}
	
}

@Service
class UserRepositoryUserDetailsService implements UserDetailsService {
	
	private final UserRepository userRepository;

	UserRepositoryUserDetailsService(UserRepository userRepository) {
		this.userRepository = userRepository;
	}
	
	public static class UserUserDetails implements UserDetails {

		
		private static final long serialVersionUID = 5733513286423778759L;

		private final User user;

		private final Set<GrantedAuthority> authorities;

		public UserUserDetails(User user) {
			this.user = user;
			this.authorities = this.user.getAuthorities().stream()
					.map(au -> new SimpleGrantedAuthority("ROLE_" + au.getAuthority()))
					.collect(Collectors.toSet());
		}

		public User getUser() {
			return user;
		}

		@Override
		public Collection<? extends GrantedAuthority> getAuthorities() {
			return this.authorities;
		}

		@Override
		public String getPassword() {
			return this.user.getPassword();
		}

		@Override
		public String getUsername() {
			return this.user.getEmail();
		}

		@Override
		public boolean isAccountNonExpired() {
			return true;
		}

		@Override
		public boolean isAccountNonLocked() {
			return true;
		}

		@Override
		public boolean isCredentialsNonExpired() {
			return true;
		}

		@Override
		public boolean isEnabled() {
			return true;
		}

	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		User usr = this.userRepository.findByEmail(username);
		if (null != usr) {
			return new UserUserDetails(usr);
		}
		else
			throw new UsernameNotFoundException("couldn't find " + username + "!");
	}

}

interface MessageRepository extends JpaRepository<Message, Long> {

	String QUERY = "select m from Message m where m.id = ?1";

	@Query(QUERY)
	@RolesAllowed("ROLE_ADMIN")
	Message findByIdRolesAllowed(Long id);
	
	@Query(QUERY)
	@Secured(value={"ROLE_ADMIN","ROLE_USER"})
	Message findByIdSecured(Long id);
	
	@Query(QUERY)
	@PreAuthorize(value = "hasRole('ADMIN')")
	Message findByIdPreAuthorized(Long id); 
	
	@Query(QUERY)
	@PostAuthorize("@authz.check(returnObject, principal?.user )")
	Message findByIdPostAuthorized(Long id); 
	
	@Query("select m from Message m where m.to.id = ?#{  principal?.user?.id  }")
	Page<Message> findMessagesFor(Pageable pageable);
}

@Service("authz")
class AuthService {

	public boolean check(Message msg, User user) {
		System.out.println("checking asking user: " + user.getEmail() + ", messgae for: " + msg.getTo().getEmail());
		return msg.getTo().getId().equals(user.getId());
	}
}

interface UserRepository extends JpaRepository<User, Long> {

	User findByEmail(String username);	
}

interface AuthorityRepository extends JpaRepository<Authority, Long> {
}

@Entity
@AllArgsConstructor
@NoArgsConstructor
@Data
@EntityListeners(AuditingEntityListener.class)
class Message{
	@Id
	@GeneratedValue
	private Long id;
	
	private String text;
	
	@OneToOne
	private User to;
	
	@CreatedBy
	private String createdBy;

	@CreatedDate
	@Temporal(TemporalType.TIMESTAMP)
	private Date created;
	
	@LastModifiedBy
	private String updatedBy;
	
	@LastModifiedDate
	@Temporal(TemporalType.TIMESTAMP)
	private Date updatedDate;
	
	public Message(String text, User to) {
		this.text = text;
		this.to = to;
	}
	
}

@Entity
@AllArgsConstructor
@NoArgsConstructor
@EqualsAndHashCode(exclude = "authorities")
@ToString
@Data
class User{
	@Id
	@GeneratedValue
	private Long id;
	
	private String email;
	
	private String password;
	
	@ManyToMany(mappedBy = "users")
	private List<Authority> authorities = new ArrayList<>();	
	
	public User(String email, String password, Set<Authority> authorities) {
		this.email = email;
		this.password = password;
		this.authorities.addAll(authorities);
	}

	public User(String email, String password) {
		this(email, password, new HashSet<>());
	}

	public User(String email, String password, Authority... authorities) {
		this(email, password, new HashSet<>(Arrays.asList(authorities)));
	}
}

@Entity
@AllArgsConstructor
@NoArgsConstructor
@ToString(exclude = "users")
@Data
class Authority{
	@Id
	@GeneratedValue
	private Long id;
	
	private String authority;	
	
	@ManyToMany(cascade = { CascadeType.PERSIST, CascadeType.MERGE })
	@JoinTable(name = "authority_user", joinColumns = @JoinColumn(name = "authority_id"), inverseJoinColumns = @JoinColumn(name = "user_id"))
	private List<User> users = new ArrayList<>();
	
	public Authority(String authority) {
		this.authority = authority;
	}

	public Authority(String authority, Set<User> users) {
		this.authority = authority;
		this.users.addAll(users);
	}
	

	
}