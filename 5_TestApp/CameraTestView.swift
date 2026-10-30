//  TweakForce — TestApp/CameraTestView.swift
//  EN: Shows an AVCaptureSession preview next to an overridden UIImage so you can
//      visually confirm a camera hook. If the hook replaces the camera feed, the
//      preview should match the override image.
//  RU: Показывает preview AVCaptureSession рядом с подменённым UIImage, чтобы
//      визуально подтвердить camera hook. Если хук подменяет поток, preview
//      совпадёт с подменённым изображением.
import UIKit
import AVFoundation

final class CameraTestView: UIViewController {
    private let session = AVCaptureSession()
    private let overrideImageView = UIImageView()
    private var previewLayer: AVCaptureVideoPreviewLayer?

    override func viewDidLoad() {
        super.viewDidLoad()
        title = "Камера"
        view.backgroundColor = .black
        setupPreview()
        setupOverride()
    }

    private func setupPreview() {
        guard let device = AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: device),
              session.canAddInput(input) else {
            NSLog("[TweakForce] camera unavailable (expected in simulator)")
            return
        }
        session.addInput(input)
        let layer = AVCaptureVideoPreviewLayer(session: session)
        layer.frame = CGRect(x: 0, y: 100, width: view.bounds.width, height: view.bounds.height/2 - 100)
        layer.videoGravity = .resizeAspectFill
        view.layer.addSublayer(layer)
        previewLayer = layer
        DispatchQueue.global().async { self.session.startRunning() }
    }

    private func setupOverride() {
        // EN: The override image path comes from the daemon value "camera_override".
        // RU: Путь подменённого изображения берётся из значения daemon "camera_override".
        overrideImageView.frame = CGRect(x: 0, y: view.bounds.height/2 + 10,
                                         width: view.bounds.width, height: view.bounds.height/2 - 20)
        overrideImageView.contentMode = .scaleAspectFit
        overrideImageView.backgroundColor = .darkGray
        let path = "/var/jb/var/mobile/Library/TweakForce/camera_override.jpg"
        overrideImageView.image = UIImage(contentsOfFile: path) ??
            UIImage(systemName: "photo")?.withTintColor(.white, renderingMode: .alwaysOriginal)
        view.addSubview(overrideImageView)
        let lbl = UILabel(frame: CGRect(x: 8, y: view.bounds.height/2 - 20, width: view.bounds.width-16, height: 20))
        lbl.textColor = .white; lbl.font = .systemFont(ofSize: 11)
        lbl.text = "↑ live preview   |   ↓ override (camera_override)"
        view.addSubview(lbl)
    }
}
