import java.nio.charset.StandardCharsets;

import javax.tools.ToolProvider;

import com.sun.source.tree.ClassTree;
import com.sun.source.tree.Tree.Kind;
import com.sun.source.util.JavacTask;

public final class JavaClassNameExtractor
{
    public static void main(String[] args) throws Exception
    {
        try {
            var compiler = ToolProvider.getSystemJavaCompiler();
            var fileManager = compiler.getStandardFileManager(null, null, StandardCharsets.UTF_8);
            var units = fileManager.getJavaFileObjects(args[0]);
            var task = (JavacTask) compiler.getTask(null, fileManager, null, null, null, units);
            var trees = task.parse();
            String className = null;
            for (var t : trees) {
                // modules are supported starting from java17
                // stick to java11 for now
                /*
                var mod = t.getModule();
                if (mod != null) {
                    System.err.println("java modules are not allowed: " + mod);
                    System.exit(1);
                }
                */

                var pkg = t.getPackage();
                if (pkg != null) {
                    System.err.println("java packages are not allowed: " + pkg);
                    System.exit(1);
                }

                var cls = t.getTypeDecls();
                for (var c : cls) {
                    var ct = (ClassTree) c;
                    if (ct.getKind() == Kind.CLASS && className == null) {
                        // FIXME: check modifiers
                        //System.out.println("Modifiers: " + ct.getModifiers());
                        className = ct.getSimpleName().toString();
                    }
                }
            }
            if (className == null) {
                System.err.println("no class found");
                System.exit(1);
            }
            System.out.println(className);
        } catch (Exception e) {
            // ignore errors, just pretend to work ok hoping that the compiler will fail later
            System.out.println("CheckFailed");
            System.exit(0);
        }
    }
}
