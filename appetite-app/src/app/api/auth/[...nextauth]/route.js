// pages/api/auth/[...nextauth].js

import NextAuth from "next-auth";
import Providers from "next-auth/providers";
import { MongoDBAdapter } from "@auth/mongodb-adapter";
import clientPromise from "@/libs/mongoConnect";
import bcrypt from "bcrypt";
import mongoose from "mongoose";
import { User } from '@/models/User';
import { UserInfo } from "@/models/UserInfo";

// Module-level variable for mongoose connection
let mongooseConnection;

async function connectToDatabase() {
  if (!mongooseConnection) {
    mongooseConnection = mongoose.connect(process.env.MONGO_URL, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
  }
  return mongooseConnection;
}

const authOptions = {
  secret: process.env.SECRET,
  adapter: MongoDBAdapter(clientPromise),
  providers: [
    Providers.Google({
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    }),
    Providers.Credentials({
      name: "Credentials",
      credentials: {
        email: { label: "Email", type: "email", placeholder: "test@example.com" },
        password: { label: "Password", type: "password", placeholder: "password" },
      },
      async authorize(credentials) {
        const email = credentials.email;
        const password = credentials.password;

        try {
          await connectToDatabase();
          const user = await User.findOne({ email });
          if (user && bcrypt.compareSync(password, user.password)) {
            return user;
          }
          return null;
        } catch (error) {
          console.error('Error during authorization:', error);
          return null;
        }
      },
    }),
  ],
};

export default (req, res) => NextAuth(req, res, authOptions);
