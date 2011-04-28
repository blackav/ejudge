import java.io.*;

public final class a_4
{
  public static void main(String args[])
  {
    StreamTokenizer st = new StreamTokenizer(new BufferedReader(new InputStreamReader(System.in)));
    int a, b;

    st.resetSyntax();
    st.eolIsSignificant(false);
    st.wordChars(33, 255);
    st.whitespaceChars(0, 32);

    try {
      st.nextToken(); a = Integer.parseInt(st.sval);
      st.nextToken(); b = Integer.parseInt(st.sval);
      System.out.println(a + b);
    } catch (Exception x) {
      System.exit(1);
    }
  }
}
