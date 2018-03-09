package fr.sle.controllers.api;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author slemoine
 */
@RestController
@RequestMapping("/api/mycontroller")
public class MyController {

    @GetMapping
    public String getValue(){
        return "The bat is in the cave !";
    }
}
