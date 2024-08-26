using System;

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

        public string ToReadableString()
        {
            var CategoryName = Enum.GetName(typeof(DetectionCategory), Category);
            return $"Detection Info\n--------------\nCategory: \t{CategoryName}\nShort Desc: \t{ShortDesc}\nFull Desc: \t{FullDesc}";
        }
    }
}
