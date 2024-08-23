namespace SharpGuard
{
    internal class DetectionInfo
    {
        public DetectionCategory Category { get; private set; }
        public string ShortDesc { get; private set; }
        public string FullDesc { get; private set; }

        public DetectionInfo(DetectionCategory category, string shortDesc, string fullDesc)
        {
            Category = category;
            ShortDesc = shortDesc;
            FullDesc = fullDesc;
        }

        public override string ToString()
        {
            return "{'Category': " + Category + ", 'ShortDesc': '" + ShortDesc + "', 'FullDesc': '" + FullDesc + "'}";
        }
    }
}
