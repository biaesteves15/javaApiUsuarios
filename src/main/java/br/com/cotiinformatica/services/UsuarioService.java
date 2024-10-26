package br.com.cotiinformatica.services;

import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import br.com.cotiinformatica.components.JwtTokenComponent;
import br.com.cotiinformatica.components.SHA256Component;
import br.com.cotiinformatica.dtos.AutenticarUsuarioRequestDto;
import br.com.cotiinformatica.dtos.CriarUsuarioRequestDto;
import br.com.cotiinformatica.entities.Usuario;
import br.com.cotiinformatica.repositories.PerfilRepository;
import br.com.cotiinformatica.repositories.PermissaoRepository;
import br.com.cotiinformatica.repositories.UsuarioRepository;

@Service
public class UsuarioService {
	
	@Autowired
	UsuarioRepository usuarioRepository;
	
	@Autowired
	PerfilRepository perfilRepository;
	
	@Autowired
	PermissaoRepository permissaoRepository;
	
	@Autowired
	SHA256Component sha256Component;
	
	@Autowired
	JwtTokenComponent jwtTokenComponent;
	
	public String criarUsuario(CriarUsuarioRequestDto dto) {
		
		if(usuarioRepository.findByEmail(dto.getEmail()) != null)
			throw new IllegalArgumentException("O email informado já está cadastrado, tente outro.");
		
		var usuario = new Usuario();
		usuario.setId(UUID.randomUUID());
		usuario.setNome(dto.getNome());
		usuario.setEmail(dto.getEmail());
		usuario.setSenha(sha256Component.hash(dto.getSenha()));
		usuario.setPerfil(perfilRepository.findByNome("OPERADOR"));
		
		//cadastrando o usuário no banco de dados
		usuarioRepository.save(usuario);
		
		//retornando mensagem de sucesso
		return "Usuário cadastrado com sucesso.";

	}
	
	public String autenticarUsuario(AutenticarUsuarioRequestDto dto) {
		
		var usuario = usuarioRepository.findByEmailAndSenha(dto.getEmail(), sha256Component.hash(dto.getSenha()));
		
		if(usuario == null)
			throw new IllegalArgumentException("Usuário inválido.");
		
		var token = jwtTokenComponent.generateToken(usuario.getId());
		
		return token;
	}

}
