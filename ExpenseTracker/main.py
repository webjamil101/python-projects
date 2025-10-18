from expense_tracker import ExpenseTracker
import tkinter as tk

def main():
    root = tk.Tk()
    app = ExpenseTracker(root)
    root.mainloop()

if __name__ == "__main__":
    main()