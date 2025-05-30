function simplifyOSName(osString) { 
    // "Muhtemelen Bilinmeyen" ifadesini "Yanıt Vermeyen Cihaz" ile değiştir 
    if (osString.includes("Muhtemelen Bilinmeyen") || osString === "Bilinmeyen" || osString.includes("Diğer Cihaz")) { 
        return "Yanıt Vermeyen Cihaz"; 
    } 
 
    // İşletim sistemi adını al, sürüm ve parantez içi bilgileri kaldır 
    let osName = "Yanıt Vermeyen Cihaz"; 
 
    if (osString.includes("Windows")) { 
        osName = "Windows"; 
    } else if (osString.includes("Android")) { 
        osName = "Android"; 
    } else if (osString.includes("Linux") || osString.includes("Unix")) { 
        // Android kelimesi önceden kontrol edildiği için buraya düşerse sadece Linux/Unix'tir 
        osName = "Linux/Unix"; 
    } else if (osString.includes("macOS") || osString.includes("iOS") || osString.includes("Apple")) { 
        osName = "Apple"; 
    } else if (osString.includes("Router") || osString.includes("Network Device") || osString.includes("Ağ Cihazı")) { 
        osName = "Router/Ağ Cihazı"; 
    } 
 
    return osName; 
} 
