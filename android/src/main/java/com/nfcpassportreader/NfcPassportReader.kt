package com.nfcpassportreader

import android.content.Context
import android.nfc.tech.IsoDep
import android.util.Log
import com.nfcpassportreader.utils.*
import com.nfcpassportreader.dto.*
import net.sf.scuba.smartcards.CardService
import org.jmrtd.BACKeySpec
import org.jmrtd.PassportService
import org.jmrtd.lds.CardSecurityFile
import org.jmrtd.lds.PACEInfo
import org.jmrtd.lds.icao.DG11File
import org.jmrtd.lds.icao.DG1File
import org.jmrtd.lds.icao.DG2File
import org.jmrtd.lds.iso19794.FaceImageInfo

class NfcPassportReader(context: Context) {
  private val bitmapUtil = BitmapUtil(context)
  private val dateUtil = DateUtil()
  private val TAG = "NfcPassportReader"

  fun readPassport(isoDep: IsoDep, bacKey: BACKeySpec, includeImages: Boolean): NfcResult {
    Log.d(TAG, "Starting passport reading process")
    isoDep.timeout = 10000
    Log.d(TAG, "IsoDep timeout set to 10000ms")

    val cardService = CardService.getInstance(isoDep)
    Log.d(TAG, "CardService instance created")
    cardService.open()
    Log.d(TAG, "CardService opened")

    val service = PassportService(
      cardService,
      PassportService.NORMAL_MAX_TRANCEIVE_LENGTH,
      PassportService.DEFAULT_MAX_BLOCKSIZE,
      false,
      false
    )
    Log.d(TAG, "PassportService created with normal max tranceive length: ${PassportService.NORMAL_MAX_TRANCEIVE_LENGTH}, default max blocksize: ${PassportService.DEFAULT_MAX_BLOCKSIZE}")
    service.open()
    Log.d(TAG, "PassportService opened")

    var paceSucceeded = false
    try {
      Log.d(TAG, "Attempting to get EF_CARD_SECURITY stream: ${PassportService.EF_CARD_SECURITY}")
      val cardSecurityFile =
        CardSecurityFile(service.getInputStream(PassportService.EF_CARD_SECURITY))
      Log.d(TAG, "Successfully loaded CardSecurityFile")
      val securityInfoCollection = cardSecurityFile.securityInfos
      Log.d(TAG, "Extracted security infos, count: ${securityInfoCollection.size}")

      for (securityInfo in securityInfoCollection) {
        if (securityInfo is PACEInfo) {
          Log.d(TAG, "Found PACEInfo with objectId: ${securityInfo.objectIdentifier} and parameterId: ${securityInfo.parameterId}")
          service.doPACE(
            bacKey,
            securityInfo.objectIdentifier,
            PACEInfo.toParameterSpec(securityInfo.parameterId),
            null
          )
          Log.d(TAG, "PACE authentication succeeded")
          paceSucceeded = true
        }
      }
    } catch (e: Exception) {
      Log.e(TAG, "PACE process failed with error: ${e.message}")
      Log.e(TAG, "Stack trace: ", e)
      e.printStackTrace()
    }
    Log.d(TAG, "PACE succeeded: $paceSucceeded")

    Log.d(TAG, "Sending select applet command with PACE result: $paceSucceeded")
    service.sendSelectApplet(paceSucceeded)
    Log.d(TAG, "Select applet command sent")

    if (!paceSucceeded) {
      Log.d(TAG, "PACE did not succeed, attempting fallback")
      try {
        Log.d(TAG, "Attempting to read EF_COM: ${PassportService.EF_COM}")
        service.getInputStream(PassportService.EF_COM).read()
        Log.d(TAG, "Successfully read EF_COM")
      } catch (e: Exception) {
        Log.e(TAG, "EF_COM read failed with error: ${e.message}")
        Log.e(TAG, "EF_COM error stack trace: ", e)
        e.printStackTrace()

        Log.d(TAG, "Attempting BAC authentication")
        service.doBAC(bacKey)
        Log.d(TAG, "BAC authentication completed")
      }
    }

    val nfcResult = NfcResult()
    Log.d(TAG, "Created new NfcResult object")

    try {
        Log.d(TAG, "Attempting to read DG1 file: ${PassportService.EF_DG1}")
        val dg1In = service.getInputStream(PassportService.EF_DG1)
        Log.d(TAG, "Successfully got DG1 input stream")
        val dg1File = DG1File(dg1In)
        Log.d(TAG, "Successfully parsed DG1 file")
        val mrzInfo = dg1File.mrzInfo
        Log.d(TAG, "Successfully extracted MRZ info")

        try {
            Log.d(TAG, "Attempting to read DG11 file: ${PassportService.EF_DG11}")
            val dg11In = service.getInputStream(PassportService.EF_DG11)
            Log.d(TAG, "Successfully got DG11 input stream")
            val dg11File = DG11File(dg11In)
            Log.d(TAG, "Successfully parsed DG11 file")

            Log.d(TAG, "Extracting name details from DG11")
            val name = dg11File.nameOfHolder.substringAfterLast("<<").replace("<", " ")
            val surname = dg11File.nameOfHolder.substringBeforeLast("<<")
            Log.d(TAG, "Name extraction complete: $surname, $name")

            nfcResult.firstName = name
            nfcResult.lastName = surname
            Log.d(TAG, "Set name in result object")

            Log.d(TAG, "Extracting place of birth")
            nfcResult.placeOfBirth = dg11File.placeOfBirth.joinToString(separator = " ")
            Log.d(TAG, "Place of birth: ${nfcResult.placeOfBirth}")

            Log.d(TAG, "Extracting identity number and gender")
            nfcResult.identityNo = mrzInfo.personalNumber
            nfcResult.gender = mrzInfo.gender.toString()
            Log.d(TAG, "Identity number: ${nfcResult.identityNo}, Gender: ${nfcResult.gender}")

            Log.d(TAG, "Converting dates")
            nfcResult.birthDate = dateUtil.convertFromNfcDate(dg11File.fullDateOfBirth)
            nfcResult.expiryDate = dateUtil.convertFromMrzDate(mrzInfo.dateOfExpiry)
            Log.d(TAG, "Birth date: ${nfcResult.birthDate}, Expiry date: ${nfcResult.expiryDate}")

            Log.d(TAG, "Extracting document details")
            nfcResult.documentNo = mrzInfo.documentNumber
            nfcResult.nationality = mrzInfo.nationality
            nfcResult.mrz = mrzInfo.toString()
            Log.d(TAG, "Document number: ${nfcResult.documentNo}, Nationality: ${nfcResult.nationality}")

            if (includeImages) {
                try {
                    Log.d(TAG, "Images requested, attempting to read DG2 file: ${PassportService.EF_DG2}")
                    val dg2In = service.getInputStream(PassportService.EF_DG2)
                    Log.d(TAG, "Successfully got DG2 input stream")
                    val dg2File = DG2File(dg2In)
                    Log.d(TAG, "Successfully parsed DG2 file")
                    val faceInfos = dg2File.faceInfos
                    Log.d(TAG, "Retrieved face infos, count: ${faceInfos.size}")
                    
                    val allFaceImageInfos: MutableList<FaceImageInfo> = ArrayList()
                    for (faceInfo in faceInfos) {
                        Log.d(TAG, "Processing face info with face image count: ${faceInfo.faceImageInfos.size}")
                        allFaceImageInfos.addAll(faceInfo.faceImageInfos)
                    }
                    
                    if (allFaceImageInfos.isNotEmpty()) {
                        Log.d(TAG, "Found ${allFaceImageInfos.size} face images, extracting first one")
                        val faceImageInfo = allFaceImageInfos.iterator().next()
                        val image = bitmapUtil.getImage(faceImageInfo)
                        Log.d(TAG, "Successfully extracted image")
                        nfcResult.originalFacePhoto = image
                    } else {
                        Log.d(TAG, "No face images found in DG2")
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Error processing DG2 file: ${e.message}")
                    Log.e(TAG, "DG2 error stack trace: ", e)
                }
            }

            Log.d(TAG, "DG11 file length: ${dg11File.length}")
            if (dg11File.length > 0) {
                Log.d(TAG, "Passport reading completed successfully")
                return nfcResult
            } else {
                Log.e(TAG, "DG11 file is empty")
                throw Exception("DG11 file is empty")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error processing DG11 file: ${e.message}")
            Log.e(TAG, "DG11 error stack trace: ", e)
            throw e
        }
    } catch (e: Exception) {
        Log.e(TAG, "Error processing DG1 file: ${e.message}")
        Log.e(TAG, "DG1 error stack trace: ", e)
        throw e
    }
  }
}
