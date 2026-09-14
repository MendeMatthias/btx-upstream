// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_QT_MODELNETPAGE_H
#define BITCOIN_QT_MODELNETPAGE_H

#include <QWidget>

#include <string>

class ClientModel;

namespace Ui {
    class ModelNetPage;
}

/** Models-first desktop page: Models, Downloads, Shared Models, Collections,
 *  Preservation, Peers, Identity. Same RPC names as btx-cli. Does not spend,
 *  auto-fetch, or start inference. */
class ModelNetPage : public QWidget
{
    Q_OBJECT

public:
    explicit ModelNetPage(QWidget *parent = nullptr);
    ~ModelNetPage();

    void setClientModel(ClientModel *model);
    void showOpenedUri(const QString& uri);

public Q_SLOTS:
    void refresh();

private:
    Ui::ModelNetPage *ui;
    ClientModel* m_client_model{nullptr};

    QString callRpc(const std::string& method) const;
    void refreshConsent();
};

#endif // BITCOIN_QT_MODELNETPAGE_H
