#include <QApplication>
#include "GuardView.h"

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    app.setApplicationName("FydelGuard");
    app.setApplicationVersion("1.0.0");

    GuardView view;
    return app.exec();
}
