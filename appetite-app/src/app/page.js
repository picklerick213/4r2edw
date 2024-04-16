import Hero from "./components/layout/Hero";
import HomeMenu from "./components/layout/HomeMenu";
import { RiFacebookCircleFill } from "react-icons/ri";
import { RiInstagramFill } from "react-icons/ri";
import { RiTwitterXFill } from "react-icons/ri";
import { RiTiktokLine } from "react-icons/ri";

import Link from 'next/link';


export default function Home() {
  return (
    <>
    <Hero />
    <HomeMenu />
    </>
  )
}
