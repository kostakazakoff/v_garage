<?php

namespace App\Controller;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Attribute\Route;

#[Route('/api/auth/', name: 'api_auth_')]
class AuthController extends AbstractController
{
    public function __construct(
        private EntityManagerInterface $em,
        private UserPasswordHasherInterface $passwordHasher
        )
    {
    }
    #[Route('register', name: 'register', methods: ['POST'])]
    public function register(Request $request): Response
    {
        $credentials = json_decode($request->getContent());
        $email = $credentials->email;
        $plainTextPassword = $credentials->password;

        $newUser = new User();
        $password = $this->passwordHasher->hashPassword(
            $newUser,
            $plainTextPassword
        );

        $newUser->setEmail($email);
        $newUser->setPassword($password);
        $newUser->setUsername($email);
        $newUser->setRoles(['ROLE_USER']);

        $this->em->persist($newUser);
        $this->em->flush();

        return $this->json(["message" => "success"]);
    }
}
