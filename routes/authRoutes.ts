import express, { Router, Request, Response } from "express";
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
import { PrismaClient } from "@prisma/client";
import { authenticateUser } from "../authMiddleware";

const prisma = new PrismaClient();
const router: Router = express.Router();

interface AuthRequest extends Request {
  user?: any;
}

router.get("/products", async (req: Request, res: Response) => {
  try {
    const products = await prisma.product.findMany();
    res.json(products);
  } catch (error) {
    console.error("Error fetching products:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

router.post("/signup", async (req: Request, res: Response) => {
  const { username, password } = req.body;

  try {
    // Check if user already exists
    const existingUser = await prisma.user.findUnique({
      where: {
        username,
      },
    });

    if (existingUser) {
      return res.status(400).json({ error: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await prisma.user.create({
      data: {
        username,
        password: hashedPassword,
      },
    });

    res.status(201).json({ message: "User created successfully" });
  } catch (error) {
    console.error("Error creating user:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});
router.post("/login", async (req: Request, res: Response) => {
  const { username, password } = req.body;

  try {
    const user = await prisma.user.findUnique({
      where: {
        username,
      },
    });

    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: user.id },
      (process.env.JWT_SECRET as string) || "secret",
      {
        expiresIn: "1h",
      }
    );

    res.json({ token });
  } catch (error) {
    console.error("Error during login:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

router.post("/logout", (req: Request, res: Response) => {
  try {
    res.json({ message: "Logout successful" });
  } catch (error) {
    console.error("Logout failed:", error);
    res.status(500).json({ error: "Logout failed" });
  }
});

router.use(authenticateUser);
router.post("/addProduct", async (req: AuthRequest, res: Response) => {
  if (!req.user) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const { productName, imageLink, description, price } = req.body;
  const userId = req.user.userId;

  try {
    const newProduct = await prisma.product.create({
      data: {
        name: productName,
        imageLink,
        description,
        price,
        userId,
      },
    });

    res
      .status(201)
      .json({ message: "Product added successfully", product: newProduct });
  } catch (error) {
    console.error("Error adding product:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

router.delete(
  "/deleteProduct/:productId",
  async (req: AuthRequest, res: Response) => {
    // Check if user is logged in
    if (!req.user) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const productId = parseInt(req.params.productId);
    const userId = req.user.userId;

    try {
      const product = await prisma.product.findUnique({
        where: {
          id: productId,
        },
      });
      if (!product || product.userId !== userId) {
        return res.status(403).json({
          error: "Forbidden: You are not authorized to delete this product",
        });
      }
      await prisma.product.delete({
        where: {
          id: productId,
        },
      });

      res.json({ message: "Product deleted successfully" });
    } catch (error) {
      console.error("Error deleting product:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  }
);
router.get("/products/:productId", async (req: Request, res: Response) => {
  const productId = parseInt(req.params.productId);

  try {
    const product = await prisma.product.findUnique({
      where: {
        id: productId,
      },
    });

    if (!product) {
      return res.status(404).json({ error: "Product not found" });
    }

    res.json(product);
  } catch (error) {
    console.error("Error fetching product:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

router.put("/products/:productId", async (req: AuthRequest, res: Response) => {
  const productId = parseInt(req.params.productId);
  const { name, imageLink, description, price } = req.body;
  const userId = req.user.userId; // Retrieve user ID from authenticated user

  try {
    const existingProduct = await prisma.product.findUnique({
      where: {
        id: productId,
      },
    });

    if (!existingProduct) {
      return res.status(404).json({ error: "Product not found" });
    }

    // Check if the user is the owner of the product
    if (existingProduct.userId !== userId) {
      return res.status(403).json({
        error: "Forbidden: You are not authorized to edit this product",
      });
    }

    const updatedProduct = await prisma.product.update({
      where: {
        id: productId,
      },
      data: {
        name,
        imageLink,
        description,
        price,
      },
    });

    res.json(updatedProduct);
  } catch (error) {
    console.error("Error updating product:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
