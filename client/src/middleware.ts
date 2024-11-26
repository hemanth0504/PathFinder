import { clerkMiddleware, createRouteMatcher } from "@clerk/nextjs/server";
import { NextResponse } from "next/server";
import { clerkClient } from '@clerk/clerk-sdk-node';

// Create route matchers for student and teacher routes
const isStudentRoute = createRouteMatcher(["/user/(.*)"]);
const isTeacherRoute = createRouteMatcher(["/teacher/(.*)"]);

// Public routes where users should be able to access without signing in
const isPublicPage = createRouteMatcher(["/courses", "/signup", "/signin", "/","/search","/checkout"]);

export default clerkMiddleware(async (auth, req) => {
  try {
    const { sessionClaims } = await auth();
    const sessionId = sessionClaims?.sid;

    // If the user is not signed in and is trying to access a protected page, redirect to home
    if (!sessionId) {
      // Skip redirecting if we are on a public page like /signin or /signup
      if (!req.url.includes("/signup") && !req.url.includes("/signin") && !isPublicPage(req)) {
        const homeUrl = new URL("/", req.url);
        return NextResponse.redirect(homeUrl);
      }
    }

    // If session exists, fetch user session and metadata
    if (sessionId) {
      const session = await clerkClient.sessions.getSession(sessionId);
      const user = await clerkClient.users.getUser(session.userId);

      // Access user metadata
      const userMetadata = user.publicMetadata || user.privateMetadata;
      const userRole = userMetadata?.userType || "student"; // Default to "student"

      // Redirect logic based on role
      if (isStudentRoute(req)) {
        if (userRole !== "student") {
          const teacherCourseUrl = new URL("/teacher/courses", req.url);
          return NextResponse.redirect(teacherCourseUrl); // Redirect to teacher courses page
        }
      }

      if (isTeacherRoute(req)) {
        if (userRole !== "teacher") {
          const userCourseUrl = new URL("/user/courses", req.url);
          return NextResponse.redirect(userCourseUrl); // Redirect to student courses page
        }
      }
    }

    // Proceed with the request if all checks pass
    return NextResponse.next();
  } catch (error) {
    console.error('Error fetching metadata or session:', error);
    // On error, we can also redirect to home page instead of sign-in
    const homeUrl = new URL("/", req.url);
    return NextResponse.redirect(homeUrl);
  }
});

export const config = {
  matcher: [
    "/((?!_next|[^?]*\\.(?:html?|css|js(?!on)|jpe?g|webp|png|gif|svg|ttf|woff2?|ico|csv|docx?|xlsx?|zip|webmanifest)).*)",
    "/(api|trpc)(.*)",
  ],
};
