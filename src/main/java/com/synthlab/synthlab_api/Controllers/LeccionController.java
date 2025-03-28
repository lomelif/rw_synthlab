package com.synthlab.synthlab_api.Controllers;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.synthlab.synthlab_api.DTOs.ContenidoDTO;
import com.synthlab.synthlab_api.Entities.Leccion;
import com.synthlab.synthlab_api.Entities.LeccionContenido;
import com.synthlab.synthlab_api.Services.LeccionService;

import java.util.List;

@RestController
@RequestMapping("/lecciones")
public class LeccionController {
    private final LeccionService leccionService;

    public LeccionController(LeccionService leccionService) {
        this.leccionService = leccionService;
    }

    @GetMapping("/{id}")
    public Leccion getLeccion(@PathVariable Long id) {
        return leccionService.getLeccion(id);
    }

    @GetMapping
    public List<Leccion> getTitulos() {
        return leccionService.getTitulos();
    }

    @GetMapping("/contenidos")
    public List<LeccionContenido> getContenidos() {
        return leccionService.getContenidos();
    }

    @PostMapping
    public ResponseEntity<Leccion> createLeccion(@RequestBody Leccion leccion) {
        Leccion nuevaLeccion = leccionService.createLeccion(leccion);
        return ResponseEntity.status(HttpStatus.CREATED).body(nuevaLeccion);
    }

    @PostMapping("/contenidos/{id}")
    public ResponseEntity<LeccionContenido> addContenido(
            @PathVariable Long id,
            @RequestBody ContenidoDTO request) {
        
        LeccionContenido nuevaDescripcion = leccionService.addContenido(id, request);
        return ResponseEntity.status(HttpStatus.CREATED).body(nuevaDescripcion);
    }
}
