package com.lucky.patcher

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import org.jf.dexlib2.DexFileFactory
import org.jf.dexlib2.Opcodes
import org.jf.dexlib2.dexbacked.DexBackedClassDef
import java.io.File
import java.security.MessageDigest
import java.util.concurrent.Executors

class MainActivity : AppCompatActivity() {
    private val executor = Executors.newSingleThreadExecutor()
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        
        val recyclerView = findViewById<RecyclerView>(R.id.recyclerView)
        recyclerView.layoutManager = LinearLayoutManager(this)
        
        loadApps(recyclerView)
    }
    
    private fun loadApps(recyclerView: RecyclerView) {
        executor.execute {
            val pm = packageManager
            val packages = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
            val apps = mutableListOf<AppAdapter.AppInfo>()
            
            for (pkg in packages) {
                val ai = pkg.applicationInfo ?: continue
                val isSystem = (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0
                apps.add(AppAdapter.AppInfo(
                    name = ai.loadLabel(pm).toString(),
                    packageName = pkg.packageName,
                    apkPath = ai.sourceDir,
                    versionName = pkg.versionName ?: "?",
                    isSystem = isSystem
                ))
            }
            apps.sortBy { it.name }
            
            runOnUiThread {
                recyclerView.adapter = AppAdapter(apps) { app ->
                    showAppDetails(app)
                }
            }
        }
    }
    
    private fun showAppDetails(app: AppAdapter.AppInfo) {
        executor.execute {
            val sb = StringBuilder()
            try {
                val pm = packageManager
                val pi = pm.getPackageInfo(app.packageName, 
                    PackageManager.GET_PERMISSIONS or PackageManager.GET_SIGNATURES)
                
                sb.append("=== ${app.name} ===\n")
                sb.append("Package: ${app.packageName}\n")
                sb.append("Version: ${app.versionName}\n")
                sb.append("APK: ${app.apkPath}\n")
                sb.append("System: ${if (app.isSystem) "oui" else "non"}\n\n")
                
                sb.append("=== PERMISSIONS ===\n")
                pi.requestedPermissions?.forEach { 
                    sb.append("• $it\n")
                } ?: sb.append("(aucune)\n")
                
                sb.append("\n=== SIGNATURE ===\n")
                pi.signatures?.firstOrNull()?.let { sig ->
                    val md = MessageDigest.getInstance("SHA-256")
                    val hash = md.digest(sig.toByteArray())
                    sb.append(hash.joinToString(":") { "%02X".format(it) }\n")
                } ?: sb.append("(aucune)\n")
                
                sb.append("\n=== DEX ===\n")
                try {
                    val container = DexFileFactory.loadDexContainer(File(app.apkPath), Opcodes.getDefault())
                    var classCount = 0
                    var methodCount = 0
                    for (entryName in container.dexEntryNames) {
                        val dex = container.getEntry(entryName)!!
                        classCount += dex.classes.size
                        for (cls in dex.classes) {
                            methodCount += (cls as DexBackedClassDef).methods.size
                        }
                    }
                    sb.append("Dex files: ${container.dexEntryNames.size}\n")
                    sb.append("Classes: $classCount\n")
                    sb.append("Methods: $methodCount\n")
                } catch (e: Exception) {
                    sb.append("Dex error: ${e.message}\n")
                }
                
            } catch (e: Exception) {
                sb.append("Error: ${e.message}")
            }
            
            runOnUiThread {
                Toast.makeText(this, sb.toString().take(2000), Toast.LENGTH_LONG).show()
            }
        }
    }
    
    override fun onDestroy() {
        super.onDestroy()
        executor.shutdown()
    }
}
