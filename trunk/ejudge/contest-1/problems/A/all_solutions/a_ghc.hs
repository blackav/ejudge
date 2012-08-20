main :: IO ()
main = getContents >>= print . sum . map read . words

