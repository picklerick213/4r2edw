import bcrypt from "bcrypt";
import mongoose from "mongoose";
import { User } from '@/models/User';
import NextAuth, { getServerSession } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import GoogleProvider from "next-auth/providers/google";
import { MongoDBAdapter } from "@auth/mongodb-adapter";
import clientPromise from "@/libs/mongoConnect";
import { UserInfo } from "../../../../models/UserInfo";

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

export const authOptions = {
  secret: process.env.SECRET,
  adapter: MongoDBAdapter(clientPromise),
  providers: [
    GoogleProvider({
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    }),
    CredentialsProvider({
      name: 'Credentials',
      id: 'credentials',
      credentials: {
        email: { label: "Email", type: "email", placeholder: "test@example.com" },
        password: { label: "Password", type: "password", placeholder: "password" },
      },
      async authorize(credentials, req) {
        const email = credentials?.email;
        const password = credentials?.password;

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

export async function isAdmin() {
  const session = await getServerSession(authOptions);
  const userEmail = session?.user?.email;
  if (!userEmail) {
    return false;
  }
  try {
    await connectToDatabase();
    const userInfo = await UserInfo.findOne({ email: userEmail });
    if (!userInfo) {
      return false;
    }
    return userInfo.admin;
  } catch (error) {
    console.error('Error during admin check:', error);
    return false;
  }
}

const handler = NextAuth(authOptions);

export { handler as GET, handler as POST };
