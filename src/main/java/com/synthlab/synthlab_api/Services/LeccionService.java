package com.synthlab.synthlab_api.Services;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import com.synthlab.synthlab_api.DTOs.ContenidoDTO;
import com.synthlab.synthlab_api.Entities.Leccion;
import com.synthlab.synthlab_api.Entities.LeccionContenido;
import com.synthlab.synthlab_api.Repositories.LeccionContenidoRepository;
import com.synthlab.synthlab_api.Repositories.LeccionRepository;

import java.util.List;

@Service
public class LeccionService {
    private final LeccionRepository leccionRepository;
    private final LeccionContenidoRepository leccionContenidoRepository;

    public LeccionService(LeccionRepository leccionRepository, LeccionContenidoRepository leccionContenidoRepository) {
        this.leccionRepository = leccionRepository;
        this.leccionContenidoRepository = leccionContenidoRepository;
    }

    public Leccion getLeccion(Long id) {
        return leccionRepository.findById(id).orElse(null);
    }

    public List<Leccion> getTitulos() {
        return leccionRepository.findAll();
    }

    public List<LeccionContenido> getContenidos() {
        return leccionRepository.findAll().stream()
                .flatMap(leccion -> leccion.getContenidos().stream())
                .toList();
    }

    public Leccion createLeccion(Leccion leccion) {
        return leccionRepository.save(leccion);
    }

    public LeccionContenido addContenido(Long leccionId, ContenidoDTO request) {
        Leccion leccion = leccionRepository.findById(leccionId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Lección no encontrada"));
    
        LeccionContenido contenido = new LeccionContenido();
        contenido.setContenido(request.getContenido());
        contenido.setLeccion(leccion);
    
        return leccionContenidoRepository.save(contenido);
    }

}

