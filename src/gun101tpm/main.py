import flet as ft
import os
import threading
from gun101tpm.handler import encrypt_file, decrypt_file
from gun101tpm.backends import check_tpm_available

def main(page: ft.Page):
    page.title = "GUN-101-TPM Vault"
    page.theme_mode = ft.ThemeMode.LIGHT
    
    # Skeuomorphic background (simulating brushed metal/aluminum)
    page.bgcolor = "#D1D5DB"
    page.padding = 20
    
    # Skeuomorphic Colors
    COLOR_LED_GREEN = "#10B981"
    COLOR_LED_RED = "#EF4444"
    COLOR_TEXT_EMBOSSED = "#374151"
    
    # Common Skeuomorphic Shadow
    SHADOW_DROP = ft.BoxShadow(
        spread_radius=1,
        blur_radius=10,
        color=ft.colors.with_opacity(0.3, "#000000"),
        offset=ft.Offset(4, 4),
    )
    SHADOW_INNER = ft.BoxShadow(
        spread_radius=1,
        blur_radius=10,
        color=ft.colors.with_opacity(0.8, "#FFFFFF"),
        offset=ft.Offset(-4, -4),
    )

    # State variables
    selected_file_path = None

    # File Picker - Flet 0.86.5 API
    # No on_result parameter; use pick_files() async method instead
    file_picker = ft.FilePicker()
    page.overlay.append(file_picker)

    def pick_file_async():
        """Trigger file picker and return selected file path."""
        nonlocal selected_file_path
        # pick_files() is an async method that returns FilePickerResultEvent
        # We use page.run_thread to avoid blocking the UI
        def on_pick_result(e):
            nonlocal selected_file_path
            if e.files and len(e.files) > 0:
                selected_file_path = e.files[0].path
                selected_file_text.value = os.path.basename(selected_file_path)
            else:
                selected_file_path = None
                selected_file_text.value = "INSERT MEDIA"
            page.update()
        
        # In Flet 0.86.5, we can use the on_result event or call pick_files directly
        # Here we use the on_result event approach which is still supported
        file_picker.on_result = on_pick_result
        page.run_thread(file_picker.pick_files)

    def check_hardware_status():
        try:
            if check_tpm_available():
                return "KEYSTORE: SECURE", COLOR_LED_GREEN, ft.icons.VERIFIED_USER
            else:
                return "KEYSTORE: OFFLINE", COLOR_LED_RED, ft.icons.GPP_BAD
        except Exception:
            return "KEYSTORE: FAULT", COLOR_LED_RED, ft.icons.ERROR

    status_text, status_color, status_icon = check_hardware_status()

    # --- UI Components ---

    def show_snack(message, color=COLOR_LED_GREEN):
        page.snack_bar = ft.SnackBar(
            content=ft.Text(message, color="#FFFFFF", weight=ft.FontWeight.W_600),
            bgcolor=color,
            behavior=ft.SnackBarBehavior.FLOATING,
            shape=ft.RoundedRectangleBorder(radius=10)
        )
        page.snack_bar.open = True
        page.update()

    # File Picker UI
    def browse_files(e):
        pick_file_async()

    # File Picker Trigger Button
    browse_btn = ft.Container(
        content=ft.Row([
            ft.Icon(ft.icons.EJECT, color="#1F2937"),
            ft.Text("INSERT MEDIA", weight=ft.FontWeight.W_900, color="#1F2937", size=16)
        ], alignment=ft.MainAxisAlignment.CENTER),
        width=300,
        height=60,
        bgcolor="#E5E7EB",
        border_radius=12,
        border=ft.border.all(1, "#FFFFFF"),
        shadow=[SHADOW_DROP, SHADOW_INNER],
        on_click=browse_files,
        ink=True
    )

    # Skeuomorphic LCD Display for file name
    selected_file_text = ft.Text("INSERT MEDIA", color="#374151", weight=ft.FontWeight.BOLD, font_family="monospace")
    
    lcd_display = ft.Container(
        content=selected_file_text,
        bgcolor="#9CA3AF",  # LCD grey background
        padding=15,
        border_radius=5,
        border=ft.border.all(2, "#4B5563"),
        shadow=[
            ft.BoxShadow(blur_radius=5, color=ft.colors.with_opacity(0.5, "#000000"), offset=ft.Offset(2, 2))
        ]
    )

    # Skeuomorphic Input Field
    password_field = ft.TextField(
        label="AUTHORIZATION CODE",
        password=True,
        can_reveal_password=True,
        bgcolor="#F3F4F6",
        color="#111827",
        border_color="#9CA3AF",
        border_width=2,
        border_radius=8,
    )

    # --- Actions ---

    def perform_encryption(e):
        if not selected_file_path or not password_field.value:
            show_snack("MEDIA AND AUTHORIZATION REQUIRED.", COLOR_LED_RED)
            return

        def _encrypt_task():
            try:
                with open(selected_file_path, 'rb') as f:
                    data = f.read()
                
                encrypted_data = encrypt_file(data, password_field.value)
                
                out_path = selected_file_path + ".gun101"
                with open(out_path, 'wb') as f:
                    f.write(encrypted_data)
                
                show_snack(f"SEALED: {os.path.basename(out_path)}", COLOR_LED_GREEN)
                password_field.value = ""
                page.update()
            except Exception as ex:
                show_snack(f"FAULT: {str(ex)}", COLOR_LED_RED)

        threading.Thread(target=_encrypt_task).start()

    def perform_decryption(e):
        if not selected_file_path or not password_field.value:
            show_snack("MEDIA AND AUTHORIZATION REQUIRED.", COLOR_LED_RED)
            return

        def _decrypt_task():
            try:
                with open(selected_file_path, 'rb') as f:
                    data = f.read()
                
                decrypted_data = decrypt_file(data, password_field.value)
                
                out_path = selected_file_path.replace(".gun101", "") if selected_file_path.endswith(".gun101") else selected_file_path + ".decrypted"
                with open(out_path, 'wb') as f:
                    f.write(decrypted_data)
                
                show_snack(f"EXTRACTED: {os.path.basename(out_path)}", COLOR_LED_GREEN)
                password_field.value = ""
                page.update()
            except Exception as ex:
                show_snack(f"FAULT: {str(ex)}", COLOR_LED_RED)

        threading.Thread(target=_decrypt_task).start()

    # --- Reusable Skeuomorphic Button ---
    def create_physical_button(text, icon, on_click):
        return ft.Container(
            content=ft.Row([
                ft.Icon(icon, color="#1F2937"),
                ft.Text(text, weight=ft.FontWeight.W_900, color="#1F2937", size=16)
            ], alignment=ft.MainAxisAlignment.CENTER),
            width=300,
            height=60,
            bgcolor="#E5E7EB",
            border_radius=12,
            border=ft.border.all(1, "#FFFFFF"),
            shadow=[SHADOW_DROP, SHADOW_INNER],
            on_click=on_click,
            ink=True
        )

    # --- Views ---

    # Skeuomorphic LED Status indicator
    header = ft.Container(
        content=ft.Row([
            ft.Container(width=12, height=12, border_radius=6, bgcolor=status_color, shadow=[ft.BoxShadow(blur_radius=8, color=status_color)]),
            ft.Text(status_text, color=COLOR_TEXT_EMBOSSED, weight=ft.FontWeight.BOLD, font_family="monospace")
        ], alignment=ft.MainAxisAlignment.CENTER),
        padding=10,
        bgcolor="#D1D5DB",
        border_radius=5,
        shadow=[ft.BoxShadow(blur_radius=2, color=ft.colors.with_opacity(0.2, "#000000"), offset=ft.Offset(1, 1))]
    )

    def route_change(route):
        nonlocal selected_file_path
        page.views.clear()
        
        # HOME VIEW
        page.views.append(
            ft.View(
                "/",
                [
                    header,
                    ft.Container(height=40),
                    # Embossed Title
                    ft.Text(
                        "HARDWARE VAULT", 
                        size=36, 
                        weight=ft.FontWeight.W_900, 
                        color="#D1D5DB",
                        style=ft.TextStyle(
                            shadow=ft.BoxShadow(blur_radius=2, color="#000000", offset=ft.Offset(1, 1))
                        ),
                        text_align=ft.TextAlign.CENTER
                    ),
                    ft.Text("TPM-101 SERIES", size=16, color="#6B7280", weight=ft.FontWeight.BOLD, text_align=ft.TextAlign.CENTER),
                    ft.Container(height=60),
                    create_physical_button("ENGAGE LOCK (ENCRYPT)", ft.icons.LOCK, lambda _: page.go("/encrypt")),
                    ft.Container(height=20),
                    create_physical_button("DISENGAGE LOCK (DECRYPT)", ft.icons.LOCK_OPEN, lambda _: page.go("/decrypt")),
                ],
                bgcolor="#D1D5DB",
                horizontal_alignment=ft.CrossAxisAlignment.CENTER
            )
        )

        # ENCRYPT VIEW
        if page.route == "/encrypt":
            selected_file_path = None
            selected_file_text.value = "INSERT MEDIA"
            password_field.value = ""
            page.views.append(
                ft.View(
                    "/encrypt",
                    [
                        ft.AppBar(title=ft.Text("ENGAGE LOCK", color="#1F2937", weight=ft.FontWeight.BOLD), bgcolor="#D1D5DB"),
                        header,
                        ft.Container(height=30),
                        browse_btn,
                        ft.Container(height=20),
                        lcd_display,
                        ft.Container(height=20),
                        password_field,
                        ft.Container(height=40),
                        create_physical_button("SEAL HARDWARE", ft.icons.FINGERPRINT, perform_encryption)
                    ],
                    bgcolor="#D1D5DB",
                    horizontal_alignment=ft.CrossAxisAlignment.CENTER
                )
            )

        # DECRYPT VIEW
        if page.route == "/decrypt":
            selected_file_path = None
            selected_file_text.value = "INSERT MEDIA"
            password_field.value = ""
            page.views.append(
                ft.View(
                    "/decrypt",
                    [
                        ft.AppBar(title=ft.Text("DISENGAGE LOCK", color="#1F2937", weight=ft.FontWeight.BOLD), bgcolor="#D1D5DB"),
                        header,
                        ft.Container(height=30),
                        browse_btn,
                        ft.Container(height=20),
                        lcd_display,
                        ft.Container(height=20),
                        password_field,
                        ft.Container(height=40),
                        create_physical_button("AUTHENTICATE", ft.icons.FINGERPRINT, perform_decryption)
                    ],
                    bgcolor="#D1D5DB",
                    horizontal_alignment=ft.CrossAxisAlignment.CENTER
                )
            )
        page.update()

    def view_pop(view):
        page.views.pop()
        top_view = page.views[-1]
        page.go(top_view.route)

    page.on_route_change = route_change
    page.on_view_pop = view_pop
    page.go(page.route)

if __name__ == "__main__":
    ft.app(target=main)