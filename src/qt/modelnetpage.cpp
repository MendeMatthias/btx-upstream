// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <qt/modelnetpage.h>
#include <qt/forms/ui_modelnetpage.h>

#include <qt/clientmodel.h>
#include <qt/guiutil.h>

#include <common/args.h>
#include <interfaces/node.h>
#include <univalue.h>

#ifdef ENABLE_MODELNET
#include <modelnet/firstrun.h>
#include <modelnet/resource_uri.h>
#endif

#include <QKeyEvent>
#include <QKeySequence>
#include <QPlainTextEdit>
#include <QPushButton>

#include <stdexcept>

ModelNetPage::ModelNetPage(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::ModelNetPage)
{
    ui->setupUi(this);
    connect(ui->refreshButton, &QPushButton::clicked, this, &ModelNetPage::refresh);
    connect(ui->copyUriButton, &QPushButton::clicked, this, &ModelNetPage::copyOpenedUri);
    ui->uriDisplayLabel->installEventFilter(this);
    ui->uriRowWidget->setVisible(false);
    refresh();
}

ModelNetPage::~ModelNetPage()
{
    delete ui;
}

void ModelNetPage::setClientModel(ClientModel *model)
{
    m_client_model = model;
    refresh();
}

void ModelNetPage::showOpenedUri(const QString& uri)
{
    refresh();
#ifdef ENABLE_MODELNET
    m_full_uri = QString::fromStdString(modelnet::CopyUri(uri.toStdString()));
    const std::string display = modelnet::ShortDisplayUri(m_full_uri.toStdString());
    ui->uriDisplayLabel->setText(QString::fromStdString(display));
    ui->uriRowWidget->setVisible(!m_full_uri.isEmpty());
    const QString note = tr("Opened resource URI (not a payment, not a spend):\n%1\nCopy uses the full URI, not the short display.\n\n")
                              .arg(QString::fromStdString(display));
#else
    m_full_uri = uri;
    ui->uriDisplayLabel->setText(uri);
    ui->uriRowWidget->setVisible(!uri.isEmpty());
    const QString note = tr("Opened resource URI (not a payment, not a spend):\n%1\n\n").arg(uri);
#endif
    ui->modelsOutput->setPlainText(note + ui->modelsOutput->toPlainText());
}

void ModelNetPage::copyOpenedUri()
{
    if (m_full_uri.isEmpty()) return;
    GUIUtil::setClipboard(m_full_uri);
}

bool ModelNetPage::eventFilter(QObject* obj, QEvent* ev)
{
    if (obj == ui->uriDisplayLabel && ev->type() == QEvent::KeyPress) {
        const auto* ke = static_cast<QKeyEvent*>(ev);
        if (ke->matches(QKeySequence::Copy)) {
            copyOpenedUri();
            return true;
        }
    }
    return QWidget::eventFilter(obj, ev);
}

QString ModelNetPage::callRpc(const std::string& method) const
{
#ifdef ENABLE_MODELNET
    if (!m_client_model) {
        return tr("Node RPC is not connected. Use btx-cli %1 on the restricted local model endpoint.")
            .arg(QString::fromStdString(method));
    }
    try {
        UniValue params(UniValue::VARR);
        const UniValue result = m_client_model->node().executeRpc(method, params, /*uri=*/"");
        return QString::fromStdString(result.write(2));
    } catch (const UniValue& e) {
        return QString::fromStdString(e.write(2)) + QLatin1Char('\n') +
               tr("If the node cannot reach btx-modeld, the same method is available via btx-cli %1.")
                   .arg(QString::fromStdString(method));
    } catch (const std::exception& e) {
        return QString::fromStdString(e.what()) + QLatin1Char('\n') +
               tr("Use btx-cli %1 against the restricted local model endpoint.")
                   .arg(QString::fromStdString(method));
    }
#else
    return tr("Model network support was not compiled into this GUI. Use btx-cli %1.")
        .arg(QString::fromStdString(method));
#endif
}

void ModelNetPage::refreshConsent()
{
#ifdef ENABLE_MODELNET
    std::string err;
    modelnet::FirstRunConsent consent;
    const fs::path path = modelnet::FirstRunConsentPath(gArgs.GetDataDirNet());
    const bool loaded = modelnet::LoadFirstRunConsent(path, consent, err);
    uint64_t env_bytes = 0;
    std::string env_err;
    const bool env_budget = modelnet::EnvHasPositiveStorageBudget(env_bytes, env_err);
    const bool payload_ok = (loaded && modelnet::AllowPayloadStorage(consent)) || env_budget;
    QString text;
    if (loaded) {
        text = tr("Consent file: %1\nStorage: %2 bytes | seed=%3 | preserve_rare=%4 | consented_unix=%5")
                   .arg(GUIUtil::PathToQString(path),
                        QString::number(consent.storage_bytes),
                        QString::fromUtf8(modelnet::SeedModeName(consent.seed)),
                        consent.preserve_rare ? QStringLiteral("true") : QStringLiteral("false"),
                        QString::number(consent.consented_unix));
    } else {
        text = tr("No first-run consent file (%1). Payload storage stays 0 until a finite budget is allocated.")
                   .arg(QString::fromStdString(err));
    }
    if (env_budget) {
        text += QLatin1Char('\n') + tr("BTX_MODEL_STORAGE env budget: %1 bytes.").arg(env_bytes);
    }
    text += QLatin1Char('\n') +
            (payload_ok ? tr("Payload storage: allowed (positive budget). Automatic spend remains 0.")
                        : tr("Payload storage: refused (storage_bytes == 0). No auto-fetch."));
    ui->consentLabel->setText(text);
#else
    ui->consentLabel->setText(tr("Model network was not compiled into this GUI."));
#endif
}

void ModelNetPage::refresh()
{
    refreshConsent();
    const QString rpc_note = tr("\n\nRPC: %1 (same name as CLI). This page never calls getmodel/importmodel automatically.");
    ui->modelsOutput->setPlainText(
        tr("getmodelnetworkinfo") + QLatin1Char('\n') + callRpc("getmodelnetworkinfo") +
        QLatin1String("\n\n") + tr("listmodels") + QLatin1Char('\n') + callRpc("listmodels") +
        rpc_note.arg(QStringLiteral("getmodelnetworkinfo, listmodels")));
    ui->downloadsOutput->setPlainText(
        tr("getmodeljob") + QLatin1Char('\n') + callRpc("getmodeljob") +
        rpc_note.arg(QStringLiteral("getmodeljob")));
    ui->sharedOutput->setPlainText(
        tr("Seeded/shared inventory is the same listmodels RPC. Demand-seed is -modelseed=auto after a positive budget; this page does not advertise new models by itself.") +
        QLatin1String("\n\n") + callRpc("listmodels") +
        rpc_note.arg(QStringLiteral("listmodels")));
    ui->collectionsOutput->setPlainText(
        tr("Collections are signed immutable membership snapshots.\n"
           "Preview or subscribe with:\n"
           "  btx-cli resolveresource\n"
           "  btx-cli subscribemodelcollection\n"
           "This GUI does not auto-subscribe or auto-fetch.") +
        rpc_note.arg(QStringLiteral("subscribemodelcollection")));
    ui->preservationOutput->setPlainText(
        tr("getmodelpolicy") + QLatin1Char('\n') + callRpc("getmodelpolicy") +
        rpc_note.arg(QStringLiteral("getmodelpolicy")));
    ui->peersOutput->setPlainText(
        tr("getmodelpeers") + QLatin1Char('\n') + callRpc("getmodelpeers") +
        rpc_note.arg(QStringLiteral("getmodelpeers")));
    ui->identityOutput->setPlainText(
        tr("Research identities are not spending keys and not the wallet.\n\nlistmodelidentities\n") +
        callRpc("listmodelidentities") +
        rpc_note.arg(QStringLiteral("listmodelidentities, createmodelidentity")));
}
