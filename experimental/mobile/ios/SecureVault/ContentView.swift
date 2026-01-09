import SwiftUI
import LocalAuthentication

struct ContentView: View {
    @State private var isUnlocked = false
    @State private var statusMessage = "Vault Locked"
    
    var body: some View {
        VStack(spacing: 20) {
            Image(systemName: "lock.shield")
                .resizable()
                .frame(width: 80, height: 100)
                .foregroundColor(.blue)
            
            Text("SecureVault")
                .font(.largeTitle)
                .fontWeight(.bold)
            
            if isUnlocked {
                Text("Vault Unlocked")
                    .foregroundColor(.green)
                List {
                    Text("example.com - user1")
                    Text("github.com - dev")
                }
            } else {
                Text(statusMessage)
                    .foregroundColor(.gray)
                
                Button(action: authenticate) {
                    Label("Unlock with FaceID", systemImage: "faceid")
                        .padding()
                        .background(Color.blue)
                        .foregroundColor(.white)
                        .cornerRadius(10)
                }
            }
        }
    }
    
    func authenticate() {
        let context = LAContext()
        var error: NSError?
        
        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            let reason = "Unlock your SecureVault"
            
            context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { success, authenticationError in
                DispatchQueue.main.async {
                    if success {
                        self.isUnlocked = true
                        // Load vault data here using VaultCrypto class
                    } else {
                        self.statusMessage = "Authentication failed"
                    }
                }
            }
        } else {
            self.statusMessage = "Biometrics not available"
        }
    }
}
