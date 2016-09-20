#ifndef BLOCKEXPLORER_H
#define BLOCKEXPLORER_H

#include <QDialog>

namespace Ui { class BlockExplorer; }
class ClientModel;

class BlockExplorer : public QDialog {
    Q_OBJECT

public:
    explicit BlockExplorer(QWidget *parent = 0);
    ~BlockExplorer();

    void setClientModel(ClientModel *model);
    void setTxID(const QString &TxID);

public slots:
    void blockClicked();
    void txClicked();
    void updateExplorer(bool);

private:
    Ui::BlockExplorer *ui;
    ClientModel *clientModel;

private slots:
    /* Open the block explorer window */
    void gotoBlockExplorer(QString TxID = "");
};

#endif /* BLOCKEXPLORER_H */
